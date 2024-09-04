import * as secp256k1 from 'secp256k1';

// Function to calculate modular exponentiation
function modExp(base: bigint, exponent: bigint, modulus: bigint): bigint {
    let result = BigInt(1);
    let b = base % modulus;
    let e = exponent;

    while (e > BigInt(0)) {
        if ((e & BigInt(1)) === BigInt(1)) {
            result = (result * b) % modulus;
        }
        b = (b * b) % modulus;
        e >>= BigInt(1);
    }

    return result;
}

// Function implementing Baby-step Giant-step to solve discrete logarithm
function babyStepGiantStep(target: Buffer, base: bigint, modulus: bigint, startRange: bigint, endRange: bigint): bigint | null {
    const m = BigInt(Math.ceil(Math.sqrt(Number(modulus))));
    const babySteps: Map<bigint, bigint> = new Map();

    console.log(`Calculating BSGS with m = ${m.toString()}`);

    // Baby-step phase
    let current = BigInt(1);
    for (let j = BigInt(0); j < m; j++) {
        babySteps.set(current, j);
        current = (current * base) % modulus;

        // Check the size of the Map to avoid memory issues
        if (babySteps.size > 1e6) { // Adjust as needed
            console.warn("Map size is getting very large.");
            break;
        }
    }

    console.log(`Baby Steps phase complete. Starting Giant Steps phase.`);

    // Giant-step phase
    const invBase = modExp(base, modulus - BigInt(2), modulus); // Modular inverse of base
    const giantStepFactor = modExp(invBase, m, modulus);
    current = BigInt('0x' + target.toString('hex'));

    for (let i = BigInt(0); i < m; i++) {
        if (babySteps.has(current)) {
            let j = babySteps.get(current)!;
            const privateKey = i * m + j;

            // Ensure private key is within the specified range
            if (privateKey >= startRange && privateKey <= endRange) {
                console.log(`Private key found: ${privateKey.toString(16)}`);
                return privateKey;
            }
        }
        current = (current * giantStepFactor) % modulus;

        // Progress logging
        if (i % BigInt(10000) === BigInt(0)) {
            console.log(`Giant Step: i = ${i.toString()}, current = ${current.toString(16)}`);
        }
    }

    console.log('Private key not found.');
    return null;
}

export default babyStepGiantStep;
