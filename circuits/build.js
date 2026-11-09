// build.js — compile auth.circom and run the DEV Groth16 trusted setup.
//
//   node build.js            (from PPSEB/circuits)
//
// Writes into build/:
//   auth.r1cs, auth_js/auth.wasm      circuit + witness generator
//   auth_final.zkey                   proving key
//   verification_key.json             verifying key
//   Groth16Verifier.sol               generated Solidity verifier
//   poseidon_t3.json, poseidon_t4.json Poseidon constants for the Python side
//   setup_meta.json                   versions, sizes, constraint count
//
// THE SETUP IS A SINGLE-PARTY DEV CEREMONY. One local process contributes
// fresh random entropy and nothing proves it was discarded, so whoever ran
// this script could forge proofs. It is not secure for real use (R6.14).

const { spawn } = require("child_process");
const fs = require("fs");
const path = require("path");
const snarkjs = require("snarkjs");

const ROOT = __dirname;
const BUILD = path.join(ROOT, "build");
const CIRCUIT = path.join(ROOT, "auth.circom");
const R1CS = path.join(BUILD, "auth.r1cs");
const WASM = path.join(BUILD, "auth_js", "auth.wasm");
const PTAU_POWER = 12; // depth-4 AuthProof is ~3.2k constraints at circom's default -O1
const DEV_ENTROPY = require("crypto").randomBytes(64).toString("hex");
const COMPILE_TIMEOUT_MS = 5 * 60 * 1000;

function log(msg) { console.log(`[build] ${msg}`); }

// Read from disk: snarkjs does not export "./package.json".
function version(pkg) {
  return JSON.parse(fs.readFileSync(path.join(ROOT, "node_modules", pkg, "package.json"), "utf8")).version;
}

function upToDate(target) {
  return fs.existsSync(target) && fs.statSync(target).mtimeMs > fs.statSync(CIRCUIT).mtimeMs;
}

// circom2 is circom compiled to WASI. Asked for --r1cs and --wasm in one run it
// writes the r1cs and then never finishes (observed on Windows), while each
// flag on its own completes in seconds. So run it twice, at the same default
// optimisation level: the witness layout of auth.wasm must match auth.r1cs.
function circom(flag) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [
      path.join(ROOT, "node_modules", "circom2", "cli.js"),
      "auth.circom", flag, "-o", "build",
    ], { cwd: ROOT });
    let output = "";
    const timer = setTimeout(() => { child.kill(); reject(new Error("circom2 timed out")); },
      COMPILE_TIMEOUT_MS);
    const onData = (chunk) => {
      process.stdout.write(chunk);
      output += chunk;
      if (output.includes("Everything went okay")) {
        clearTimeout(timer);
        child.kill();
        resolve();
      }
    };
    child.stdout.on("data", onData);
    child.stderr.on("data", onData);
    child.on("exit", (code) => {
      clearTimeout(timer);
      if (output.includes("Everything went okay") || (code === 0 && fs.existsSync(WASM))) resolve();
      else reject(new Error(`circom2 ${flag} exited with ${code}`));
    });
  });
}

async function compile() {
  fs.rmSync(R1CS, { force: true });
  fs.rmSync(path.join(BUILD, "auth_js"), { recursive: true, force: true });
  await circom("--r1cs");
  await circom("--wasm");
}

async function main() {
  fs.mkdirSync(BUILD, { recursive: true });

  if (upToDate(R1CS) && upToDate(WASM)) {
    log("auth.r1cs and auth.wasm are newer than auth.circom; skipping compile");
  } else {
    log("compiling auth.circom with circom2 (WASM build of circom)");
    await compile();
  }

  const r1cs = await snarkjs.r1cs.info(R1CS);
  log(`constraints: ${r1cs.nConstraints}, public inputs: ${r1cs.nPubInputs}`);
  // Groth16 needs a domain of at least constraints + public inputs + 1.
  if (r1cs.nConstraints + r1cs.nPubInputs + 1 > 2 ** PTAU_POWER) {
    throw new Error(`circuit needs more than 2^${PTAU_POWER} constraints`);
  }

  const ptau0 = { type: "mem" };
  const ptau1 = { type: "mem" };
  const ptauFinal = path.join(BUILD, `pot${PTAU_POWER}_final.ptau`);
  log(`powers of tau 2^${PTAU_POWER} (single-party dev contribution)`);
  await snarkjs.powersOfTau.newAccumulator(await curve(), PTAU_POWER, ptau0);
  await snarkjs.powersOfTau.contribute(ptau0, ptau1, "dev-1", DEV_ENTROPY + "/ptau");
  await snarkjs.powersOfTau.preparePhase2(ptau1, ptauFinal);

  const zkey0 = { type: "mem" };
  const zkeyFinal = path.join(BUILD, "auth_final.zkey");
  log("groth16 setup + one dev contribution");
  await snarkjs.zKey.newZKey(R1CS, ptauFinal, zkey0);
  await snarkjs.zKey.contribute(zkey0, zkeyFinal, "dev-1", DEV_ENTROPY + "/zkey");

  const vkey = await snarkjs.zKey.exportVerificationKey(zkeyFinal);
  fs.writeFileSync(path.join(BUILD, "verification_key.json"), JSON.stringify(vkey, null, 1));

  const templates = { groth16: fs.readFileSync(
    path.join(ROOT, "node_modules", "snarkjs", "templates", "verifier_groth16.sol.ejs"), "utf8") };
  const sol = await snarkjs.zKey.exportSolidityVerifier(zkeyFinal, templates);
  fs.writeFileSync(path.join(BUILD, "Groth16Verifier.sol"), sol);

  const constants = JSON.parse(fs.readFileSync(path.join(ROOT,
    "node_modules/circomlibjs/src/poseidon_constants.json"), "utf8"));
  for (const t of [3, 4]) {
    fs.writeFileSync(path.join(BUILD, `poseidon_t${t}.json`), JSON.stringify({
      t, rounds_full: 8, rounds_partial: t === 3 ? 57 : 56,
      C: constants.C[t - 2], M: constants.M[t - 2],
      source: "circomlibjs Poseidon reference constants",
    }));
  }

  fs.writeFileSync(path.join(BUILD, "setup_meta.json"), JSON.stringify({
    circuit: "auth.circom", depth: 4, constraints: r1cs.nConstraints,
    public_inputs: ["root", "nullifier", "scope_id", "epoch_tag"],
    ptau_power: PTAU_POWER, curve: "bn128",
    snarkjs: version("snarkjs"),
    circom2: version("circom2"),
    circomlib: version("circomlib"),
    zkey_bytes: fs.statSync(zkeyFinal).size,
    trusted_setup: "single-party local dev ceremony; unaudited; not suitable for real use",
  }, null, 1));
  log("done");
  process.exit(0);
}

async function curve() {
  const { getCurveFromName } = require("ffjavascript");
  return getCurveFromName("bn128");
}

main().catch((err) => { console.error(err); process.exit(1); });
