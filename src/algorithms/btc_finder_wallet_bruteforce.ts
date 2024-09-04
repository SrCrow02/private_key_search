const bitcoin = require('bitcoinjs-lib');
const secp256k1 = require('secp256k1');
const worker_threads = require("worker_threads");

class KeyFinderBrute {
    // Helper method to convert BigInt to a 32-byte Buffer
    bigIntToBuffer(bigInt: BigInt): Buffer {
        const hex = bigInt.toString(16).padStart(64, '0');
        return Buffer.from(hex, 'hex');
    }

    // Method to find the private key
    findPrivateKey(targetPublicKeyHex: string, startRangeHex: string, endRangeHex: string): Buffer | null {
        const startRange = BigInt(`0x${startRangeHex}`);
        const endRange = BigInt(`0x${endRangeHex}`);
        const targetPublicKey = Buffer.from(targetPublicKeyHex, 'hex');

        let currentKey = startRange;
        let keysChecked = BigInt(0);
        const startTime = Date.now();  // Start timer

        while (currentKey <= endRange) {
            const keyBuffer = this.bigIntToBuffer(currentKey);
            keysChecked += BigInt(1);

            // Show time and keys checked every 1 million keys
            if (keysChecked % BigInt(1_000_000) === BigInt(0)) {
                const elapsedTime = (Date.now() - startTime) / 1000;  // Time in seconds
                console.log(`Checked ${keysChecked.toLocaleString()} keys in ${elapsedTime} seconds`);
            }

            if (secp256k1.privateKeyVerify(keyBuffer)) {
                const publicKey = secp256k1.publicKeyCreate(keyBuffer);

                // Compare the generated public key with the target public key
                if (Buffer.compare(publicKey, targetPublicKey) === 0) {
                    console.log(`Corresponding Public Key Found: ${publicKey.toString('hex')}`);
                    console.log(`Total keys checked: ${keysChecked.toLocaleString()}`);
                    console.log(`Time taken: ${((Date.now() - startTime) / 1000).toFixed(2)} seconds`);
                    return keyBuffer;
                }
            }

            currentKey += BigInt(1);
        }

        console.log(`Total keys checked: ${keysChecked.toLocaleString()}`);
        console.log(`Time taken: ${((Date.now() - startTime) / 1000).toFixed(2)} seconds`);
        return null;
    }

    // Solve the puzzle by searching for the private key
    solvePuzzle(targetPublicKeyHex: string, startRangeHex: string, endRangeHex: string): void {
        console.log("Searching for private key...");
        const privateKeyBuffer = this.findPrivateKey(targetPublicKeyHex, startRangeHex, endRangeHex);

        if (privateKeyBuffer) {
            console.log(`Private key found: ${privateKeyBuffer.toString('hex')}`);
        } else {
            console.log("Private key not found in the given range.");
        }
    }
}

export default {KeyFinderBrute};
