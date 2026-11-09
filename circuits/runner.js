// JSON over stdin/stdout only: witness secrets never go into filenames or logs.
const fs = require('fs');
const path = require('path');
const snarkjs = require('snarkjs');
const B = path.join(__dirname, 'build');

async function main() {
  const input = JSON.parse(fs.readFileSync(0, 'utf8'));
  const start = performance.now();
  let result;
  if (input.op === 'prove') {
    result = await snarkjs.groth16.fullProve(input.witness,
      path.join(B, 'auth_js/auth.wasm'), path.join(B, 'auth_final.zkey'),
      undefined, { singleThread: true });
  } else if (input.op === 'verify') {
    const vk = JSON.parse(fs.readFileSync(path.join(B, 'verification_key.json'), 'utf8'));
    result = { valid: await snarkjs.groth16.verify(vk, input.publicSignals, input.proof) };
  } else if (input.op === 'calldata') {
    result = { calldata: await snarkjs.groth16.exportSolidityCallData(input.proof, input.publicSignals) };
  } else if (input.op === 'poseidon') {
    const poseidon = await require('circomlibjs').buildPoseidon();
    result = { value: poseidon.F.toString(poseidon(input.values.map(BigInt))) };
  } else { throw new Error('unknown operation'); }
  process.stdout.write(JSON.stringify({ ...result, elapsed_ms: performance.now() - start }));
  process.exit(0);
}
main().catch(() => { process.stderr.write('ZK operation failed'); process.exit(1); });
