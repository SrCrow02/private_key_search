import babyStepGiantStep from "./algorithms/bsgs";
import wallets from "../wallets.json"
import btc_bruteforce from "./algorithms/btc_finder_wallet_bruteforce";

function bsgs() {
    const P = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F'); // secp256k1
    const G = BigInt(2); // Base for the multiplicative group (arbitrary value)

    // The target public key in hexadecimal
    const targetPublicKeyHex = '03633cbe3ec02b9401c5effa144c5b4d22f87940259634858fc7e59b1c09937852'; 
    const targetPublicKey = Buffer.from(targetPublicKeyHex, 'hex');

    // Define the range for private keys
    const startRange = BigInt('0x200000000000000000000000000000000'); // Start of the private key range
    const endRange = BigInt('0x3ffffffffffffffffffffffffffffffff'); // End of the private key range

    // Find the private key
    const result = babyStepGiantStep(targetPublicKey, G, P, startRange, endRange);
    if (result !== null) {
        console.log(`Private key found: ${result.toString(16)}`);
    } else {
        console.log('Private key not found.');
    }
}

function brute_force() {
    const finder = new btc_bruteforce.KeyFinder();

    // Define the range for private keys
    const startRangeHex = "200000000000000000000000000000000"; // 0 in hexadecimal
    const endRangeHex = "3ffffffffffffffffffffffffffffffff"; // 2^256-1 in hexadecimal

    finder.solvePuzzle("03633cbe3ec02b9401c5effa144c5b4d22f87940259634858fc7e59b1c09937852", startRangeHex, endRangeHex);
}

function main() {
    bsgs()
}

main();

