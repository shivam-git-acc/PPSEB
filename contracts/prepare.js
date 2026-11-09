// Generated source is derived from the actual circuit proving key, never hand-written.
const fs = require('fs');
const path = require('path');
const source = path.join(__dirname, '../circuits/build/Groth16Verifier.sol');
if (fs.existsSync(source)) {
  fs.copyFileSync(source, path.join(__dirname, 'src/Groth16Verifier.sol'));
} else {
  console.log('Groth16 artifacts unavailable: signed fallback contract tests only.');
}
