export function isPrime(k) {
  if (k < 2) return false;
  if (k === 2 || k === 3) return true;
  if (k % 2 === 0) return false;
  for (let i = 3; i * i <= k; i += 2) {
    if (k % i === 0) return false;
  }
  return true;
}

export function derivedM(n, q) {
  return 2 * n * Math.ceil(Math.log2(q));
}

export function validateParams({ n, q, sigma, l }) {
  const problems = [];
  if (!isPrime(q)) problems.push(`q=${q} is not prime; the modulus must be a prime.`);
  if (n < 2) problems.push("n must be >= 2.");
  if (sigma <= 0) problems.push("sigma must be positive.");
  if (l < 1) problems.push("l must be >= 1.");
  const m = derivedM(n, q);
  if (m % n !== 0) problems.push(`m=${m} is not a multiple of n=${n}.`);
  return problems;
}
