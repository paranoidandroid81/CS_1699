/**
 * Implementation of centralized StringCoin cryptocurrency
 */

 import java.io.*;
 import java.security.*;
 import java.security.spec.*;

 public class StringCoin
 {
   public static void main(String[] args)
   {
     BufferedReader br;
     try
     {
       //create reader to read from blockchain file
       br = new BufferedReader(new FileReader(args[0]));
       String line = br.readLine();
       int lines = 0;
       while (line != null)         //count lines in file
       {
         lines++;
         line = br.readLine();
       }
     } catch (IOException e)
     {
       System.err.println(e);
       System.exit(1);        //something wrong with input file, exit
     }
     br.close();        //close file for now
     //now that we have number of lines (num of blocks), we can build blockchain
     Blockchain blockchain = new Blockchain();
     Block[] blocks = new Block[lines];
   }
}
