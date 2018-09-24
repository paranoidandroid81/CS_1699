public class InvalidDataException extends Exception
{
  String _observed;
  int error_type;
  String [] error_outputs = {"hash", "coin", "block signature", "coin signature",
  "genesis block", "block type"};
  String error_output;

  public InvalidDataException(String observed, int error_num)
  {
    _observed = observed;
    error_type = error_num;
    error_output = error_outputs[error_num];
  }

  public String toString()
  {
    return "Invalid " + error_output + ": " + _observed;
  }
}
