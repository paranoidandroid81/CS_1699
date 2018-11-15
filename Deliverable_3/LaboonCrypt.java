/*
 * CS 1699 Project 3: Non-SHA256 Puzzle
 * Fall 2018
 * Author: Michael Korst (mpk44@pitt.edu)
 */

 import java.util.*;
 import java.io.*;

 public class LaboonCrypt
 {
   /*
    * Generate initial matrix of hash results from input
    */
    public static String[][] generate_matrix(String raw_in, int verbosity)
    {
      boolean hash_verbose = (verbosity == 3) ? true : false;        //get hash info if ultraverbose
      String[][] laboon_matrix = new String[12][12];            //initalize 12x12 array
      String last_hash = raw_in;            //first index is hash of data
      //now build matrix from hashes of previous indices
      for (int i = 0; i < 12; i++)
      {
        for (int j = 0; j < 12; j++)
        {
          last_hash = LaboonHash.compute_laboon_hash(last_hash, hash_verbose);
          laboon_matrix[i][j] = last_hash;
        }
      }
      if (verbosity > 0)
      {
        System.out.println("Initial array:");
        print_matrix(laboon_matrix);
      }
      return laboon_matrix;
    }

    /*
     * Move cursor + re-calculate hash based on ASCII values of input string
     */
     public static String ascii_rehash(String[][] raw_matrix, String raw_in, int verbosity)
     {
       boolean hash_verbose = (verbosity == 3) ? true : false;        //get hash info if ultraverbose
       int curr_x = 0;
       int curr_y = 0;          //coordinates within matrix
       String curr_elem = "";         //"cursor" position in matrix
       //iterate thru input using ASCII val of each char to move within matrix, re-hash
       //modulo 12 ensures it loops around
       for (char c : raw_in.toCharArray())
       {
         curr_x += (c * 11);
         curr_x = curr_x % 12;
         curr_y += ((c + 3) * 7);
         curr_y = curr_y % 12;
         curr_elem = raw_matrix[curr_x][curr_y];
         raw_matrix[curr_x][curr_y] = LaboonHash.compute_laboon_hash(curr_elem, hash_verbose);
         if (verbosity > 1)
         {
           System.out.println("Moving " + (int)(c * 11) + " down and " + (int)((c + 3) * 7) +" right " +
           "- modifying [" + curr_x + ", " + curr_y + "] from " + curr_elem + " to " + raw_matrix[curr_x][curr_y]);
         }
       }
       if (verbosity > 0)
       {
         System.out.println("Final array:");
         print_matrix(raw_matrix);
       }
       String concat_matrix = matrix_to_string(raw_matrix);
       return LaboonHash.compute_laboon_hash(concat_matrix, hash_verbose);
     }

     /*
      * Helper method to concatenate entire matrix, create single string
      */

      private static String matrix_to_string(String[][] raw_matrix)
      {
        StringBuilder sb = new StringBuilder();         //to form string from matrix
        for (int i = 0; i < 12; i++)
        {
          for (int j = 0; j < 12; j++)
          {
            sb.append(raw_matrix[i][j]);
          }
        }
        return sb.toString();
      }

      /*
       *  Helper method to print matrix in specified format
       */
       private static void print_matrix(String[][] raw_matrix)
       {
         for (int i = 0; i < 12; i++)
         {
           for (int j = 0; j < 12; j++)
           {
             if (j == 11)
             {
               System.out.print(raw_matrix[i][j]);
             } else {
               System.out.print(raw_matrix[i][j] + " ");
             }
           }
           System.out.print("\n");
         }
       }

   public static void main(String[] args)
   {
     int verbosity_level = 0;       //0 = no flag, 1 = verbose, 2 = very verbose, 3 = ultra verbose
     if (args.length == 2)
     {
       switch (args[1])
       {
         case "-verbose":
          verbosity_level = 1;
          break;
        case "-veryverbose":
          verbosity_level = 2;
          break;
        case "-ultraverbose":
          verbosity_level = 3;
          break;
        default:
          System.err.println("Usage:\njava LaboonCrypt *string* *verbosity_flag*\n" +
          "Verbosity flag can be omitted for hash output only\nOther options: -verbose -veryverbose -ultraverbose");
          System.exit(1);
          break;
       }
     } else if (args.length == 0 || args.length > 2)
     {
       System.err.println("Usage:\njava LaboonCrypt *string* *verbosity_flag*\n" +
       "Verbosity flag can be omitted for hash output only\nOther options: -verbose -veryverbose -ultraverbose");
       System.exit(1);
     }
     String crypt_arg = args[0];   //input to hash
     String[][] init_matrix = generate_matrix(crypt_arg, verbosity_level);
     String final_hash = ascii_rehash(init_matrix, crypt_arg, verbosity_level);
     System.out.println("LaboonCrypt hash: " + final_hash);
     System.exit(0);
   }
 }
