using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Linq;

class SecurityVulnerabilities
{
    // Helper class for byte array comparison
    class ByteArrayComparer : IEqualityComparer<byte[]>
    {
        public bool Equals(byte[]? first, byte[]? second)
        {
            if (first == null || second == null)
                return first == second;
            if (first.Length != second.Length)
                return false;
            for (int i = 0; i < first.Length; i++)
            {
                if (first[i] != second[i])
                    return false;
            }
            return true;
        }

        public int GetHashCode(byte[]? obj)
        {
            if (obj == null)
                return 0;
            int result = 17;
            for (int i = 0; i < obj.Length; i++)
            {
                unchecked
                {
                    result = result * 23 + obj[i];
                }
            }
            return result;
        }
    }

    // Simulated DES encryption (for demonstration purposes)
    static byte[] SimulatedDESEncrypt(byte[] data, byte[] key)
    {
        byte[] result = new byte[data.Length];
        for (int i = 0; i < data.Length; i++)
        {
            result[i] = (byte)(data[i] ^ key[i % key.Length]);
        }
        return result;
    }

    static byte[] SimulatedDESDecrypt(byte[] data, byte[] key)
    {
        return SimulatedDESEncrypt(data, key);
    }

    // Simulated 2DES encryption
    static byte[] Simulate2DESEncrypt(byte[] plaintext, byte[] key1, byte[] key2)
    {
        var intermediate = SimulatedDESEncrypt(plaintext, key1);
        return SimulatedDESEncrypt(intermediate, key2);
    }

    // Simulated 2DES decryption
    static byte[] Simulate2DESDecrypt(byte[] ciphertext, byte[] key1, byte[] key2)
    {
        var intermediate = SimulatedDESDecrypt(ciphertext, key2);
        return SimulatedDESDecrypt(intermediate, key1);
    }

    // Generate a key within our search space for demonstration
    static byte[] GenerateDemoKey()
    {
        byte[] key = new byte[8];
        Random rnd = new Random();
        key[0] = (byte)rnd.Next(256);
        key[1] = (byte)rnd.Next(256);
        return key;
    }

    // Generate a full-size 64-bit key
    static byte[] GenerateFullKey()
    {
        byte[] key = new byte[8];
        Random rnd = new Random();
        for (int i = 0; i < 8; i++)
        {
            key[i] = (byte)rnd.Next(256);
        }
        return key;
    }

    // Meet-in-the-Middle Attack Implementation (Demo version with 16-bit keys)
    static (byte[], byte[])? MeetInTheMiddleAttack(byte[] knownPlaintext, byte[] knownCiphertext)
    {
        var intermediateTable = new Dictionary<string, (byte[] key, byte[] intermediate)>();
        int combinationsTried = 0;
        
        Console.WriteLine("\nStep 1: Pre-computing intermediate values");
        Console.WriteLine("- Trying all possible values for first key (k1)");
        Console.WriteLine("- Encrypting known plaintext with each k1");
        Console.WriteLine("- Storing results in hash table");

        // Step 1: Try all combinations for first two bytes of k1
        for (int b1 = 0; b1 < 256; b1++)
        {
            for (int b2 = 0; b2 < 256; b2++)
            {
                if (combinationsTried % 256 == 0)
                {
                    Console.Write(".");
                }

                byte[] currentK1 = new byte[8];
                currentK1[0] = (byte)b1;
                currentK1[1] = (byte)b2;
                
                byte[] intermediate = SimulatedDESEncrypt(knownPlaintext, currentK1);
                string hash = BitConverter.ToString(intermediate);
                
                if (!intermediateTable.ContainsKey(hash))
                {
                    intermediateTable[hash] = (currentK1, intermediate);
                }

                combinationsTried++;
            }
        }

        Console.WriteLine($"\nCompleted Step 1: Tried {combinationsTried:N0} key combinations");
        Console.WriteLine("\nStep 2: Searching for matching keys");
        Console.WriteLine("- Trying all possible values for second key (k2)");
        Console.WriteLine("- Decrypting known ciphertext with each k2");
        Console.WriteLine("- Looking for matches in hash table");

        // Step 2: Try all combinations for first two bytes of k2
        combinationsTried = 0;
        for (int b1 = 0; b1 < 256; b1++)
        {
            for (int b2 = 0; b2 < 256; b2++)
            {
                if (combinationsTried % 256 == 0)
                {
                    Console.Write(".");
                }

                byte[] currentK2 = new byte[8];
                currentK2[0] = (byte)b1;
                currentK2[1] = (byte)b2;
                
                byte[] possibleIntermediate = SimulatedDESDecrypt(knownCiphertext, currentK2);
                string hash = BitConverter.ToString(possibleIntermediate);

                if (intermediateTable.ContainsKey(hash))
                {
                    var (foundK1, storedIntermediate) = intermediateTable[hash];
                    
                    // Double check that this is a valid match
                    byte[] testEncrypt = Simulate2DESEncrypt(knownPlaintext, foundK1, currentK2);
                    if (new ByteArrayComparer().Equals(testEncrypt, knownCiphertext))
                    {
                        Console.WriteLine($"\n\nMatch found after trying {combinationsTried:N0} combinations in Step 2!");
                        Console.WriteLine($"Total operations performed: {(combinationsTried + intermediateTable.Count):N0}");
                        Console.WriteLine("This demonstrates how 2DES security is reduced from 2^112 to 2^57 operations");
                        Console.WriteLine("(In this demo we only used 16 bits of each key for practicality)");
                        return (foundK1, currentK2);
                    }
                }

                combinationsTried++;
            }
        }

        return null;
    }

    // Meet-in-the-Middle Attack Implementation for full keys
    static (byte[], byte[])? MeetInTheMiddleAttackFull(byte[] knownPlaintext, byte[] knownCiphertext)
    {
        var intermediateTable = new Dictionary<string, (byte[] key, byte[] intermediate)>();
        long combinationsTried = 0;
        long totalCombinations = (long)Math.Pow(2, 64); // 2^64 combinations for full key
        
        Console.WriteLine("\nStep 1: Pre-computing intermediate values");
        Console.WriteLine("- Trying all possible values for first key (k1)");
        Console.WriteLine("- Encrypting known plaintext with each k1");
        Console.WriteLine("- Storing results in hash table");
        Console.WriteLine($"- Total possible combinations: {totalCombinations:N0}");
        Console.WriteLine("WARNING: This will take an extremely long time with full keys!");
        Console.WriteLine("Press Ctrl+C to abort...");

        // Step 1: Try all combinations for full key
        for (long b0 = 0; b0 < 256; b0++)
        {
            for (long b1 = 0; b1 < 256; b1++)
            {
                for (long b2 = 0; b2 < 256; b2++)
                {
                    for (long b3 = 0; b3 < 256; b3++)
                    {
                        if (combinationsTried % 1000000 == 0)
                        {
                            Console.Write(".");
                            double progress = (double)combinationsTried / totalCombinations * 100;
                            Console.Write($"\rProgress: {progress:F6}% - Combinations tried: {combinationsTried:N0}");
                        }

                        byte[] currentK1 = new byte[8];
                        currentK1[0] = (byte)b0;
                        currentK1[1] = (byte)b1;
                        currentK1[2] = (byte)b2;
                        currentK1[3] = (byte)b3;
                        
                        byte[] intermediate = SimulatedDESEncrypt(knownPlaintext, currentK1);
                        string hash = BitConverter.ToString(intermediate);
                        
                        if (!intermediateTable.ContainsKey(hash))
                        {
                            intermediateTable[hash] = (currentK1, intermediate);
                        }

                        combinationsTried++;
                    }
                }
            }
        }

        Console.WriteLine($"\nCompleted Step 1: Tried {combinationsTried:N0} key combinations");
        Console.WriteLine("\nStep 2: Searching for matching keys");
        Console.WriteLine("- Trying all possible values for second key (k2)");
        Console.WriteLine("- Decrypting known ciphertext with each k2");
        Console.WriteLine("- Looking for matches in hash table");

        // Reset counter for step 2
        combinationsTried = 0;

        // Step 2: Try all combinations for second key
        for (long b0 = 0; b0 < 256; b0++)
        {
            for (long b1 = 0; b1 < 256; b1++)
            {
                for (long b2 = 0; b2 < 256; b2++)
                {
                    for (long b3 = 0; b3 < 256; b3++)
                    {
                        if (combinationsTried % 1000000 == 0)
                        {
                            double progress = (double)combinationsTried / totalCombinations * 100;
                            Console.Write($"\rProgress: {progress:F6}% - Combinations tried: {combinationsTried:N0}");
                        }

                        byte[] currentK2 = new byte[8];
                        currentK2[0] = (byte)b0;
                        currentK2[1] = (byte)b1;
                        currentK2[2] = (byte)b2;
                        currentK2[3] = (byte)b3;
                        
                        byte[] possibleIntermediate = SimulatedDESDecrypt(knownCiphertext, currentK2);
                        string hash = BitConverter.ToString(possibleIntermediate);

                        if (intermediateTable.ContainsKey(hash))
                        {
                            var (foundK1, storedIntermediate) = intermediateTable[hash];
                            
                            // Double check that this is a valid match
                            byte[] testEncrypt = Simulate2DESEncrypt(knownPlaintext, foundK1, currentK2);
                            if (new ByteArrayComparer().Equals(testEncrypt, knownCiphertext))
                            {
                                Console.WriteLine($"\n\nMatch found after trying {combinationsTried:N0} combinations in Step 2!");
                                Console.WriteLine($"Total operations performed: {(combinationsTried + intermediateTable.Count):N0}");
                                return (foundK1, currentK2);
                            }
                        }

                        combinationsTried++;
                    }
                }
            }
        }

        return null;
    }

    static void InteractiveMITMAttack(bool useFullKeys = false)
    {
        Console.WriteLine("\n=== Meet-in-the-Middle Attack on 2DES ===");
        Console.WriteLine("This demonstrates how 2DES can be broken using MITM attack");
        if (useFullKeys)
        {
            Console.WriteLine("Using full 64-bit keys (this will take a VERY long time!)");
            Console.WriteLine("The attack reduces security from 2^112 to 2^57 operations");
        }
        else
        {
            Console.WriteLine("Using simplified 16-bit keys for demonstration");
            Console.WriteLine("(For practical demonstration purposes only)");
        }
        
        // Get full message from user
        Console.WriteLine("\nEnter a longer message to encrypt (this will be the full plaintext):");
        Console.Write("> ");
        string fullMessage = Console.ReadLine() ?? "This is a longer message that contains some known plaintext within it.";

        // Generate keys based on mode
        byte[] key1 = useFullKeys ? GenerateFullKey() : GenerateDemoKey();
        byte[] key2 = useFullKeys ? GenerateFullKey() : GenerateDemoKey();

        // Encrypt the full message
        byte[] fullPlaintext = Encoding.UTF8.GetBytes(fullMessage);
        byte[] fullCiphertext = Simulate2DESEncrypt(fullPlaintext, key1, key2);

        Console.WriteLine("\nFull message encrypted. Now let's select a portion for the attack.");
        Console.WriteLine($"Original message: \"{fullMessage}\"");
        Console.WriteLine("Encrypted message (hex): " + BitConverter.ToString(fullCiphertext));
        
        // Select portion for attack
        int start, length;
        while (true)
        {
            Console.Write($"\nEnter start position (0-{fullMessage.Length - 1}): ");
            Console.Write("> ");
            if (!int.TryParse(Console.ReadLine(), out start) || start < 0 || start >= fullMessage.Length)
            {
                Console.WriteLine("Invalid start position. Using 0.");
                start = 0;
            }

            Console.Write($"Enter length of known plaintext to use (1-{fullMessage.Length - start}): ");
            Console.Write("> ");
            if (!int.TryParse(Console.ReadLine(), out length) || length < 1 || length > fullMessage.Length - start)
            {
                Console.WriteLine($"Invalid length. Using {Math.Min(8, fullMessage.Length - start)}.");
                length = Math.Min(8, fullMessage.Length - start);
            }

            if (length > 20)
            {
                Console.WriteLine("Warning: Using a large plaintext section may slow down the attack.");
                Console.Write("Continue? (y/n): ");
                Console.Write("> ");
                if ((Console.ReadLine()?.ToLower() ?? "n") != "y")
                {
                    continue;
                }
            }
            break;
        }

        // Extract the known plaintext-ciphertext pair
        string knownPlaintext = fullMessage.Substring(start, length);
        byte[] knownPlaintextBytes = Encoding.UTF8.GetBytes(knownPlaintext);
        byte[] knownCiphertextBytes = new byte[length];
        Array.Copy(fullCiphertext, start, knownCiphertextBytes, 0, length);

        Console.WriteLine("\nSelected plaintext-ciphertext pair:");
        Console.WriteLine($"Known plaintext: \"{knownPlaintext}\"");
        Console.WriteLine($"Corresponding ciphertext (hex): {BitConverter.ToString(knownCiphertextBytes)}");
        Console.WriteLine("\nTrue Key1 (unknown to attacker): " + BitConverter.ToString(key1));
        Console.WriteLine("True Key2 (unknown to attacker): " + BitConverter.ToString(key2));

        // Perform the attack
        Console.Write("\nAttempt to crack using Meet-in-the-Middle attack? (y/n): ");
        Console.Write("> ");
        if ((Console.ReadLine()?.ToLower() ?? "n") == "y")
        {
            Console.WriteLine("\nPerforming Meet-in-the-Middle attack...");
            var result = useFullKeys ? 
                MeetInTheMiddleAttackFull(knownPlaintextBytes, knownCiphertextBytes) :
                MeetInTheMiddleAttack(knownPlaintextBytes, knownCiphertextBytes);

            if (result.HasValue)
            {
                var (crackedKey1, crackedKey2) = result.Value;
                Console.WriteLine("\nAttack successful!");
                Console.WriteLine("Found Key1: " + BitConverter.ToString(crackedKey1));
                Console.WriteLine("Found Key2: " + BitConverter.ToString(crackedKey2));

                // Verify the attack worked
                Console.WriteLine("\nVerification:");
                
                // First verify the known portion
                byte[] decryptedKnown = Simulate2DESDecrypt(knownCiphertextBytes, crackedKey1, crackedKey2);
                Console.WriteLine($"Decrypted known portion: {Encoding.UTF8.GetString(decryptedKnown)}");
                
                // Then try to decrypt the full message
                byte[] decryptedFull = Simulate2DESDecrypt(fullCiphertext, crackedKey1, crackedKey2);
                Console.WriteLine("\nDecrypting full message with found keys:");
                Console.WriteLine($"Full decrypted message: {Encoding.UTF8.GetString(decryptedFull)}");
                
                Console.WriteLine("\nOriginal vs Found Keys:");
                Console.WriteLine("Original Key1: " + BitConverter.ToString(key1));
                Console.WriteLine("Found Key1:    " + BitConverter.ToString(crackedKey1));
                Console.WriteLine("Original Key2: " + BitConverter.ToString(key2));
                Console.WriteLine("Found Key2:    " + BitConverter.ToString(crackedKey2));
            }
            else
            {
                Console.WriteLine("\nAttack failed unexpectedly.");
                Console.WriteLine("This should not happen in our demonstration as we search the entire key space.");
            }
        }
    }

    static void Main()
    {
        while (true)
        {
            Console.Clear();
            Console.WriteLine("2DES Meet-in-the-Middle Attack Demonstration");
            Console.WriteLine("=========================================");
            Console.WriteLine("1. Run Demo Attack (16-bit keys)");
            Console.WriteLine("2. Run Full Attack (64-bit keys - VERY SLOW!)");
            Console.WriteLine("3. Exit");
            Console.Write("\nSelect an option: ");
            Console.Write("> ");

            string? choice = Console.ReadLine();
            
            switch (choice)
            {
                case "1":
                    InteractiveMITMAttack(false);
                    Console.WriteLine("\nPress any key to continue...");
                    Console.ReadKey();
                    break;
                case "2":
                    InteractiveMITMAttack(true);
                    Console.WriteLine("\nPress any key to continue...");
                    Console.ReadKey();
                    break;
                case "3":
                    return;
                default:
                    Console.WriteLine("Invalid option. Press any key to try again...");
                    Console.ReadKey();
                    break;
            }
        }
    }
} 