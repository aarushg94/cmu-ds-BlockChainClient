/***
 * authorID: aarushg
 * authorName: Aarush Gupta
 *
 * Blockchain Client Class
 *
 * This program implements a TCP client and the RSA algorithm is used to generate client ID and signature of the
 * client. It performs computation once the client ID and signature have been verified.
 */

package cmu.edu.ds.aarushg;

import org.json.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.net.Socket;
import java.net.SocketException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;
import java.util.Scanner;

public class BlockchainClient {

    /***
     * n - modulus for both the private and public keys
     * e - exponent of the public key
     * d - exponent of the private key
     */

    static BigInteger n;
    static BigInteger e;
    static BigInteger d;

    /**
     * Method: getMenuOptions()
     * This method displays the menu options for the user to select which blockchain related operations such
     * as add, view, verify, corrupt and repair the blockchain.
     */

    public void getMenuOptions() {
        System.out.println();
        System.out.println("0. View basic blockchain status.");
        System.out.println("1. Add a transaction to the blockchain.");
        System.out.println("2. Verify the blockchain.");
        System.out.println("3. View the blockchain.");
        System.out.println("4. Corrupt the chain.");
        System.out.println("5. Hide the Corruption by repairing the chain.");
        System.out.println("6. Exit");
    }

    /**
     * @param args
     */

    public static void main(String[] args) {

        BlockchainClient blockChainClient = new BlockchainClient();

        /***
         * Generate two large prime numbers with a 400 bit length. Compute n by p*q. Compute phi(n) = (p-1) * (q-1).
         * Select a small odd integer e that is relatively prime to phi(n) - 65537. Compute d as the multiplicative
         * inverse of e modulo phi(n). Concatenate e and n after converting the BigInteger to a string. Hash to
         * generate clientID.
         */

        Random rnd = new Random();
        BigInteger p = new BigInteger(400, 100, rnd);
        BigInteger q = new BigInteger(400, 100, rnd);
        n = p.multiply(q);
        BigInteger phi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));
        e = new BigInteger("65537");
        d = e.modInverse(phi);
        String eBigIntegerString = String.valueOf(e);
        String nBigIntegerString = String.valueOf(n);
        String newBigIntegerString = eBigIntegerString + nBigIntegerString;
        String hash = ComputeSHA_256_as_Hex_String(newBigIntegerString);
        String clientID = hash.substring(hash.length() - 40);
        String operationValue;
        int difficulty = 0;
        String transaction = null;
        long sTime = System.currentTimeMillis();
        Scanner scanner = new Scanner(System.in);

        /***
         * Sends a TCP request. Initializes socket, input and output streams. Starts the server and waits for
         * a connection. Display a menu for the user to perform various operations on blockchain or quit the program.
         * Responsible for asking user input in terms of block operation to perform and based on that user input
         * it further requests for inputs in required such as block ID, difficulty or transaction itself. For any
         * and all options which don't require blockID or transaction, we set it as -1 and "" for consistency
         * purposes as it needs to be sent to server where the computation takes place on the signature.
         */

        Socket clientSocket = null;
        try {
            System.out.println("---Client running---");
            int serverPort = 7777;
            clientSocket = new Socket("localhost", serverPort);
            BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            PrintWriter out = new PrintWriter(new BufferedWriter(new OutputStreamWriter(clientSocket.getOutputStream())));
            System.out.println("ClientID: " + clientID);
            while (true) {
                blockChainClient.getMenuOptions();
                System.out.print("Enter Choice: ");
                operationValue = scanner.nextLine();
                switch (Integer.parseInt(operationValue)) {
                    case 0:
                    case 5:
                        difficulty = -1;
                        transaction = "";
                        break;
                    case 1:
                        System.out.print("Enter Difficulty > 0: ");
                        try {
                            difficulty = Integer.parseInt(scanner.nextLine());
                            if (difficulty < 0) {
                                System.out.println("Difficulty must be > 0");
                                continue;
                            }
                        } catch (NumberFormatException e) {
                            System.out.println("Number Format Exception: Please Input Integer");
                            System.exit(0);
                        }
                        System.out.print("Enter transaction: ");
                        transaction = scanner.nextLine();
                        break;
                    case 2:
                        sTime = System.currentTimeMillis();
                        System.out.println("Verifying Entire Chain");
                        difficulty = -1;
                        transaction = "";
                        break;
                    case 3:
                        System.out.println("View the Blockchain");
                        difficulty = -1;
                        transaction = "";
                        break;
                    case 4:
                        System.out.print("Enter block ID of block to Corrupt: ");
                        try {
                            difficulty = Integer.parseInt(scanner.nextLine());
                        } catch (NumberFormatException e) {
                            System.out.println("Number Format Exception: Please input integer");
                            System.exit(0);
                        }
                        System.out.print("Enter new data for block " + difficulty + ": ");
                        transaction = scanner.nextLine();
                        break;
                    case 6:
                        System.out.println("Client is closing");
                        out.close();
                        break;
                    default:
                        System.out.println("Please input integer between 1 to 6");
                        continue;
                }

                /***
                 * key -> client id + public key (e+n) + user input operation + user input value for difficulty/blockID
                 * + user input String value for transaction.
                 * signature -> stores the encrypted key
                 * requestString -> concatenated string to be sent to the server separated by commas
                 * Send requestString to the server
                 * data -> Read data from the server
                 * Handling general exceptions
                 *
                 * Source for JSON Parsing: https://www.geeksforgeeks.org/parse-json-java/
                 *
                 */

                String key;
                String signature = null;
                key = clientID + newBigIntegerString + operationValue + difficulty + transaction;
                String hashedKey = ComputeSHA_256_as_Hex_String(key);
                try {
                    signature = sign(hashedKey);
                } catch (Exception e) {
                    System.out.println("Exception e");
                }
                JSONObject jsonString = new JSONObject().put("clientID", clientID)
                        .put("operationValue", operationValue)
                        .put("difficulty", difficulty)
                        .put("transaction", transaction)
                        .put("signature", signature)
                        .put("BigIntegerE", e.toString())
                        .put("BigIntegerN", n.toString());
                out.println(jsonString);
                out.flush();

                /**
                 * Based on user input and data read back by the client, this is responsible for displaying data
                 * read by the client from the server. Data is coming back in the form of a JSON object or string.
                 *
                 */

                int userExpectedOutput = Integer.parseInt(operationValue);
                Object obj = null;
                String data = in.readLine();
                switch (userExpectedOutput) {
                    case 0:
                        try {
                            obj = new JSONParser().parse(data);
                        } catch (ParseException ex) {
                            ex.printStackTrace();
                        }
                        org.json.simple.JSONObject jo = (org.json.simple.JSONObject) obj;
                        System.out.println("Current size of chain: " + (int) (long) jo.get("size"));
                        System.out.println("Current hashes per second by this machine: " + (int) (long) jo.get("hashes"));
                        System.out.println("Difficulty of most recent block: " + (int) (long) jo.get("difficulty"));
                        System.out.println("Nonce of most recent block: " + jo.get("nonce"));
                        System.out.println("Chain Hash: " + "\n" + jo.get("chainHash"));
                        break;
                    case 1:
                    case 3:
                    case 4:
                        System.out.println(data);
                        break;
                    case 2:
                        System.out.println(data);
                        long eTime = System.currentTimeMillis();
                        long elapsedTime = eTime - sTime;
                        System.out.println("Total execution time required to verify the chain was " + elapsedTime + " milliseconds");
                        break;
                    case 5:
                        System.out.println("Repairing the entire chain");
                        System.out.println(data);
                        break;
                    default:
                        System.exit(0);
                        break;
                }

            }

            /***
             * Handling socket, number format and I/O exceptions.
             */

        } catch (SocketException e) {
        } catch (NumberFormatException n) {
            System.out.println("Number format exception, please input integer only");
        } catch (IOException e) {
            System.out.println("IO Exception:" + e.getMessage());
        } finally {
            try {
                if (clientSocket != null) {
                    clientSocket.close();
                }
            } catch (IOException e) {
            }
        }
    }

    /***
     * sign() method
     * Convert to byte array. Create a new array to store 0 and add 0 as the most significant bit to make it
     * positive. Convert the same to a BigInteger and encrypt it with the private key.
     * @param message
     */

    public static String sign(String message) throws Exception {
        byte[] hexToByteArray = hexStringToByteArray(message);
        byte tempArray[] = new byte[hexToByteArray.length + 1];
        tempArray[0] = 0;
        for (int i = 0; i < hexToByteArray.length; i++) {
            tempArray[i + 1] = hexToByteArray[i];
        }
        BigInteger m = new BigInteger(tempArray);
        BigInteger c = m.modPow(d, n);
        return c.toString();
    }

    /***
     * ComputeSHA_256_as_Hex_String() method
     * Source: 'BabyHash' class
     * Create a SHA256 digest. Initialize byte array for storing the hash. Perform the hash and store
     * the result. Handling exceptions.
     * @param text
     */

    public static String ComputeSHA_256_as_Hex_String(String text) {
        try {
            MessageDigest digest;
            digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes;
            digest.update(text.getBytes("UTF-8"), 0, text.length());
            hashBytes = digest.digest();
            return convertToHex(hashBytes);
        } catch (NoSuchAlgorithmException nsa) {
            System.out.println("No such algorithm exception thrown " + nsa);
        } catch (UnsupportedEncodingException uee) {
            System.out.println("Unsupported encoding exception thrown " + uee);
        }
        return null;
    }

    /***s
     * convertToHex() method
     * Source: StackOverflow + 'BabyHash' program
     * Converts a byte array to a String. Each nibble (4 bits) of the byte array is represented by a hex character.
     * @param data
     */

    private static String convertToHex(byte[] data) {
        StringBuffer buf = new StringBuffer();
        for (int i = 0; i < data.length; i++) {
            int halfbyte = (data[i] >>> 4) & 0x0F;
            int two_halfs = 0;
            do {
                if ((0 <= halfbyte) && (halfbyte <= 9)) {
                    buf.append((char) ('0' + halfbyte));
                } else {
                    buf.append((char) ('a' + (halfbyte - 10)));
                }
                halfbyte = data[i] & 0x0F;
            } while (two_halfs++ < 1);
        }
        return buf.toString();
    }

    /***
     * hexStringToByteArray() method
     * Source: StackOverflow + 'BabySign'
     * @param s
     */

    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }
}