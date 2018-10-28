/**
 * CS 1699 Project 2: Mining
 * Fall 2018
 * Author: Michael Korst (mpk44@pitt.edu)
 */

 import java.io.*;
 import java.security.*;
 import java.security.spec.*;
 import java.util.*;
 import java.lang.StringBuilder;
 import java.nio.charset.StandardCharsets;
 import java.math.BigInteger;
 import java.lang.System;
 import java.util.regex.Pattern;
 import java.util.regex.Matcher;


 public class Mine
 {
   //maximum mining target
   public static final BigInteger MAX_TARGET = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 16);
   static final String MINE_ADDR = "1333dGpHU6gQShR596zbKHXEeSihdtoyLb";
   static int tx_fees;              //transaction fees given to miner from chosen transactions
   static int num_trans;            //for block
   static String success_hash;

   /**
    * Given some arbitrary byte array bytes, convert it to a hex string.
    * Example: [0xFF, 0xA0, 0x01] -> "FFA001"
    * Code borrowed from Laboon: Sha256Hash.java
    * @param bytes arbitrary-length array of bytes
    * @return String hex string version of byte array
    */

   public static String convertBytesToHexString(byte[] bytes)
   {
     StringBuffer toReturn = new StringBuffer();
     for (int j = 0; j < bytes.length; j++) {
       String hexit = String.format("%02x", bytes[j]);
       toReturn.append(hexit);
     }
     return toReturn.toString();
   }

   /**
    * Given some arbitrary hex string, convert it to a byte array.
    * Example: "FFA001" -> [0xFF, 0xA0, 0x01]
    * NOTE: Assumes that hex string is valid (i.e., even length)
    * Code borrowed from Laboon: PublicKeyDemo.java
    * @param hex arbitrary-length hex string
    * @return byte[] byte array version of hex string
    */

   public static byte[] convertHexToBytes(String hex)
   {
     byte[] bytes = new byte[hex.length() / 2];
     int c = 0;
     for (int j = 0; j < hex.length(); j += 2) {
       String twoHex = hex.substring(j, j + 2);
       byte byteVal = (byte) Integer.parseInt(twoHex, 16);
       bytes[c++] = byteVal;
     }
     return bytes;
   }

   /*
    * Optimize transactions to include in the block.
    * Based on the greedy algorithm solution to the knapsack problem
    * From: http://www.micsymposium.org/mics_2005/papers/paper102.pdf
    */
   public static ArrayList<String> optimize_trans(List<String> raw_trans)
   {
     int sum_weights = 0;         //for optimization, max can only be 15 (allow 1 for coinbase)
     TreeMap<Double, Integer> ratios = new TreeMap<>();              //sorts weights for greedy alg, map weights to array index
     HashMap<Integer, String> trans_map = new HashMap<>();        //maps array index to transaction
     int[] weights = new int[raw_trans.size()];
     int[] values = new int[raw_trans.size()];
     int i = 0;               //track index
     int curr_weight, curr_value;
     double curr_ratio;
     int sum_in, sum_out;           //for optimizing each trans
     //reg ex for finding coin values within transactions
     String pattern = "(>)(\\d+)";
     Pattern r = Pattern.compile(pattern);
     for (String curr : raw_trans)
     {
       sum_in = 0;
       sum_out = 0;
       trans_map.put(i, curr);                //store for later use
       String[] in_outs = curr.split(";");        //split into inputs and outputs 1st
       String[] inputs = (in_outs[0]).split(",");           //split into individual inputs
       String[] outputs = (in_outs[1]).split(",");           //split into individual inputs
       curr_weight = inputs.length + outputs.length;         //calcualate weight of trans (inputs + outputs)
       weights[i] = curr_weight;                  //store weight
       for (String output : outputs)
       {
         Matcher m = r.matcher(output);               //find trans output
         m.find();
         curr_value = Integer.parseInt(m.group(2));             //2nd group is digits we're looking for
         sum_out += curr_value;
       }
       for (String input : inputs)
       {
         Matcher n = r.matcher(input);               //find trans output
         n.find();
         curr_value = Integer.parseInt(n.group(2));             //2nd group is digits we're looking for
         sum_in += curr_value;
       }
       curr_value = sum_in - sum_out;               //tx fee equal to "change" (in-out remainder)
       values[i] = curr_value;
       curr_ratio = (double)(values[i]) / (double)(weights[i]);               //calculate value-to-weight ratio
       ratios.put(curr_ratio, i);                           //add ratio to be sorted (later will be reversed order)
       i++;
     }
     NavigableMap<Double,Integer> ratio_tree = ratios.descendingMap();            //get map of ratios in order from greatest (most value) to least
     ArrayList<String> ret_trans = new ArrayList<>();
     double curr_key;
     int curr_index;
     while (sum_weights < 16 && !ratio_tree.isEmpty())
     {
       curr_key = ratio_tree.firstKey();              //get best available current ratio
       curr_index = ratio_tree.remove(curr_key);       //removes from tree, to check weight and stuff
       curr_weight = weights[curr_index];
       curr_value = values[curr_index];
       if ((sum_weights + curr_weight) > 15)
       {
         //proceed to next transaction, too big
         continue;
       } else {
         sum_weights += curr_weight;
         tx_fees += curr_value;
         ret_trans.add(trans_map.get(curr_index));
       }
     }
     num_trans = sum_weights;                 //set for later usage
     return ret_trans;
   }

   /*
    * Calculate concat root or block hash
    * Should work generically for list concatenation hash
    */
   public static String get_concat_hash(List<String> elems)
   {
     StringBuilder sb = new StringBuilder();
     byte[] hash = null;
     for (String curr : elems)
     {
       curr = curr.replaceAll("\\r\\n|\\r|\\n", "");                 //remove carriage returns
       sb.append(curr);
     }
     try
     {
       //create SHA-256 hash of concatenated transactions
       MessageDigest md = MessageDigest.getInstance("SHA-256");
       md.update(sb.toString().getBytes());
       hash = md.digest();
     } catch (NoSuchAlgorithmException nsaex)
     {
       System.err.println("No SHA-256 algorithm found.");
 	     System.err.println("This generally should not happen...");
 	     System.exit(1);
     }
     return convertBytesToHexString(hash);
   }

   /*
    * Find nonce for block so H(block) < target
    * Nonce = 4 ASCII characters, values of 32-126 in decimal
    */
   public static String get_nonce(List<String> block_stuff, BigInteger diff_target)
   {
     StringBuilder try_nonce = new StringBuilder(4);                //nonce possibilities, 4 ASCII chars
     int i = 32;
     int j = 32;
     int k = 32;                    //4 ints to represent char code of each letter, iterate through, brute force possibilities
     int l = 32;
     BigInteger try_hash;             //used for testing hash
     try_nonce.append((char)i);                 //initialize nonce to beginning of possible ascii
     try_nonce.append((char)i);                 //initialize nonce to beginning of possible ascii
     try_nonce.append((char)i);                 //initialize nonce to beginning of possible ascii
     try_nonce.append((char)i);                 //initialize nonce to beginning of possible ascii
     for (i = 32; i < 127; i++)
     {
       try_nonce.setCharAt(0, (char)i);
       block_stuff.set(4, try_nonce.toString());
       try_hash = new BigInteger(get_concat_hash(block_stuff), 16);             //get hash in base 16 for comparison to target
       if (try_hash.compareTo(diff_target) == -1)
       {
         success_hash = try_hash.toString(16);               //store for printing
         return try_nonce.toString();                           //nonce found!
       }
       for (j = 32; j < 127; j++)
       {
         try_nonce.setCharAt(1, (char)j);
         block_stuff.set(4, try_nonce.toString());
         try_hash = new BigInteger(get_concat_hash(block_stuff), 16);             //get hash in base 16 for comparison to target
         if (try_hash.compareTo(diff_target) == -1)
         {
           success_hash = try_hash.toString(16);               //store for printing
           return try_nonce.toString();                           //nonce found!
         }
         for (k = 32; k < 127; k++)
         {
           try_nonce.setCharAt(2, (char)k);
           block_stuff.set(4, try_nonce.toString());
           try_hash = new BigInteger(get_concat_hash(block_stuff), 16);             //get hash in base 16 for comparison to target
           if (try_hash.compareTo(diff_target) == -1)
           {
             success_hash = try_hash.toString(16);               //store for printing
             return try_nonce.toString();                           //nonce found!
           }
           for (l = 32; l < 127; l++)
           {
             try_nonce.setCharAt(3, (char)l);
             block_stuff.set(4, try_nonce.toString());
             try_hash = new BigInteger(get_concat_hash(block_stuff), 16);             //get hash in base 16 for comparison to target
             if (try_hash.compareTo(diff_target) == -1)
             {
               success_hash = try_hash.toString(16);               //store for printing
               return try_nonce.toString();                           //nonce found!
             }
           }
         }
        }
      }
      return try_nonce.toString();                //probably shouldn't happen...
    }

   public static void main(String[] args)
   {
     String difficulty = args[1];            //store difficulty from command line
     BigInteger target = MAX_TARGET.divide(new BigInteger(difficulty));             //calculates block target
     long timestamp = System.currentTimeMillis();           //get current time for time stamp
     String prev_hash = args[2];          //store previous hash for block
     BufferedReader br;
     List<String> trans_list = new ArrayList<String>();         //stores each transaction
     String line;                     //each line
     try
     {
       br = new BufferedReader(new FileReader(args[0]));
       line = br.readLine();
       while (line != null)
       {
         trans_list.add(line);              //add all transactions to list
         line = br.readLine();
       }
     } catch (IOException e)
     {
       System.err.println(e);
       System.exit(1);        //something wrong with input file, exit
     }
     ArrayList<String> chosen_trans = optimize_trans(trans_list);                 //find optimal transactions for file
     //make coinbase transaction
     int reward = 50 + tx_fees;                               //50 reward plus any fees
     String coinbase = ";" + MINE_ADDR + ">" + reward;          //formats block reward correctly
     chosen_trans.add(coinbase);
     num_trans++;             //1 output trans for coinbase
     String concat_root = get_concat_hash(chosen_trans);                          //calculate concat root of chosen transactions
     String nonce = "0000";                               //initally placeholder
     List<String> block_elems = new ArrayList<String>();                        //holds all elements of block for use in hashing/nonce find
     block_elems.add(prev_hash);
     block_elems.add(Integer.toString(num_trans));
     block_elems.add(Long.toString(timestamp));
     block_elems.add(difficulty);
     block_elems.add(nonce);
     block_elems.add(concat_root);
     nonce = get_nonce(block_elems, target);                //find nonce based on target
     int leading_zeros = MAX_TARGET.toString(16).length() - success_hash.length();               //find how many leading zereos to append to match length
     StringBuilder hash_out = new StringBuilder();
     for (int z = 0; z < leading_zeros; z++)
     {
       hash_out.append("0");                  //build string with right number of leading zeroes
     }
     hash_out.append(success_hash);
     //we have nonce and transactions, can begin printing
     System.out.println("CANDIDATE BLOCK = Hash " + hash_out.toString());
     System.out.println("---");
     System.out.println(prev_hash);
     System.out.println(num_trans);
     System.out.println(timestamp);
     System.out.println(difficulty);
     System.out.println(nonce);
     System.out.println(concat_root);
     for (String elem : chosen_trans)
     {
       System.out.println(elem);
     }
     System.exit(1);              //success!
   }
}
