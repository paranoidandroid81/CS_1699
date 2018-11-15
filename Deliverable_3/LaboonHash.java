/*
 * CS 1699 Project 3: Non-SHA256 Puzzle
 * Fall 2018
 * Author: Michael Korst (mpk44@pitt.edu)
 */

 import java.util.*;
 import java.io.*;

 public class LaboonHash
 {
   private static final String INIT_VECTOR = "1AB0";              //initalization vector for hash function

   /*
    * Helper to convert chars to hex values
    */
    public static char[] char_to_hex(char[] raw_in)
    {
      char[] ret_val = new char[raw_in.length];
      for (int i = 0; i < raw_in.length; i++)
      {
        ret_val[i] = Integer.toHexString(raw_in[i] % 16).toUpperCase().charAt(0);
      }
      return ret_val;
    }

   /*
    * Merkle-Damgard strengthening per specifications
    */
    private static char[] md_strengthen(char[] raw_in)
    {
      //if multiple of 8, no need to strengthen!
      if (raw_in.length % 8 == 0)
      {
        return raw_in;
      }
      //8 chars in a block, int rounds down, so technically 1 more with padded block
      int num_blocks = raw_in.length / 8;
      int start_pad = num_blocks * 8;             //8 chars per block, use to find start of block you need to pad
      //find free spaces in last block, will use to strengthen
      int free_spaces = 8 - (raw_in.length - start_pad);
      //calculate length pad in hex w/uppercase
      String hex_pad = Integer.toHexString(raw_in.length % (int)(Math.pow(16, free_spaces))).toUpperCase();
      //now add 0 padding and length pad for strengthening on last block
      char[] pad_block = new char[num_blocks*8 + 8];           //create new array for the padded result
      //copy old into new array, so prepared for adding new in
      System.arraycopy(raw_in, 0, pad_block, 0, raw_in.length);
      //pad with 0s up to where hex pad starts
      for (int i = start_pad + (raw_in.length - start_pad); i < (pad_block.length - hex_pad.length()); i++)
      {
        pad_block[i] = '0';
      }
      int i = pad_block.length - hex_pad.length();
      //now append the length hex
      for (char c : hex_pad.toCharArray())
      {
        pad_block[i] = c;
        i++;
      }
      return pad_block;
    }

   /*
    * 1st phase of compression
    */
    private static char[] p_one_compress(String lhs, String rhs)
    {
      char[] result = new char[4];
      char[] char_lhs = lhs.toCharArray();
      char[] char_rhs = rhs.toCharArray();
      int j = 3;        //rhs index
      for (int i = 0; i < result.length; i++)
      {
        result[i] = (char)(lhs.charAt(i) + rhs.charAt(j));
        j--;
      }
      return result;
    }

    /*
     *  2nd phase of compression
     */
     private static char[] p_two_compress(String lhs, String rhs)
     {
       char[] result = new char[4];
       int j = 7;        //rhs index
       for (int i = 0; i < result.length; i++)
       {
         result[i] = (char)(lhs.charAt(i) ^ rhs.charAt(j));
         j--;
       }
       return result;
     }

     /*
      *  3rd phase of compression
      */
      private static char[] p_three_compress(String res_in)
      {
        StringBuilder sb = new StringBuilder(res_in);       //helps with building result
        char result;
        int j = 3;        //reverse result index index
        for (int i = 0; i < res_in.length(); i++)
        {
          result = (char)(sb.charAt(i) ^ sb.charAt(j));
          sb.setCharAt(i, result);
          j--;
        }
        return sb.toString().toCharArray();
      }

      /*
       *  Public method for complete LaboonHash of string
       */
       public static String compute_laboon_hash(String str_in, boolean verbose)
       {
         char[] raw_in = str_in.toCharArray();
         char[] pad_in = md_strengthen(raw_in);
         if (verbose)
         {
           System.out.println("\tPadded string: " + String.valueOf(pad_in));
           System.out.println("\tBlocks:");
           String print_blocks = String.valueOf(pad_in);
           for (int i = 0; i < pad_in.length; i += 8)
           {
             System.out.println("\t" + print_blocks.substring(i, i + 8));
           }
         }
         int num_blocks = pad_in.length / 8;          //store num of blocks for hashing
         char[][] blocks = new char[num_blocks][8];       //stores blocks for hashing
         //begin hashing functions
         int i = 0;         //track blocks
         int j = 0;         //track index in entire string
         char[] next_result = new char[4];          //use for lhs/result part of phases
         String last_result = "";             //use for printing
         for (char[] curr_block : blocks)
         {
           System.arraycopy(pad_in, j, curr_block, 0, 8);
           if (i == 0)
           {
             last_result = INIT_VECTOR;
             //first block special case, must use IV
             next_result = p_one_compress(INIT_VECTOR, String.valueOf(curr_block));
           } else {
             last_result = String.valueOf(next_result);
             next_result = p_one_compress(String.valueOf(next_result), String.valueOf(curr_block));
           }
           next_result = p_two_compress(String.valueOf(next_result), String.valueOf(curr_block));
           next_result = p_three_compress(String.valueOf(next_result));
           next_result = char_to_hex(next_result);
           if (verbose)
           {
             System.out.println("\tIterating with " + last_result + " / " + String.valueOf(curr_block) + " = " + String.valueOf(next_result));
           }
           i++;
           j += 8;
         }
         if (verbose)
         {
           System.out.println("\tFinal result: " + String.valueOf(next_result));
         }
         return String.valueOf(next_result);
       }

   public static void main(String[] args)
   {
     boolean verbosity = false;         //verbose mode?
     if (args.length == 2)
     {
       if (args[1].equals("-verbose"))
       {
         verbosity = true;
       } else {
         System.err.println("Usage:\njava LaboonHash *string* *verbosity_flag*\n" +
         "Verbosity flag can be omitted for hash output only\nOther options: -verbose");
         System.exit(1);
       }
     } else if (args.length == 0 || args.length > 2)
     {
       System.err.println("Usage:\njava LaboonHash *string* *verbosity_flag*\n" +
       "Verbosity flag can be omitted for hash output only\nOther options: -verbose");
       System.exit(1);
     }
     String laboon_arg = args[0];         //string to hash
     String result = compute_laboon_hash(laboon_arg, verbosity);
     System.out.println("LaboonHash hash = " + result);
     System.exit(0);
   }
 }
