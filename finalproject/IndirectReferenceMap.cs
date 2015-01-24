//
// Modified based on example codes in:
// http://www.troyhunt.com/2010/09/owasp-top-10-for-net-developers-part-4.html
//------------------------------------------------------------------------------

using System;
using System.Security.Cryptography;
using System.Text;
using System.Web


public static class IndirectReferenceMap
{

  // Get direct reference from the indirect version
  public static int GetDirectReference(string indirectReference)
  {
    var map = (Dictionary<String, int>)HttpContext.Current.Session["IndirMapToDir"];
    return map[indirectReference];
  }


  //Get the indirect version from the direct reference
  public static string GetIndirectReference(int directReference)
  {
    var map = (Dictionary<int, string>)HttpContext.Current.Session["DirMapToIndir"];
    return map == null ?
      AddDirectReference(directReference)
      : map[directReference];
  }


  // create the map from direct reference to indirect version
  private static String AddDirectReference(int directReference)
  {
    string indirectReference = IndirectReferenceMap.ComputeHashString(directReference);
    HttpContext.Current.Session["DirMapToIndir"] = new Dictionary<int, string>
      { {directReference, indirectReference } };
    HttpContext.Current.Session["IndirMapToDir"] = new Dictionary<string, int>
      { {indirectReference, directReference } };
    return indirectReference;
  }


  // Generate hash value from integer
  public static string ComputeHashString(int directReference)
  {
    string dirString = directReference.ToString();
    UnicodeEncoding UE = new UnicodeEncoding();

    //Convert the string into an array of bytes.
    byte[] MessageBytes = UE.GetBytes(dirString);

    SHA1Managed SHhash = new SHA1Managed();

    //Create the hash value from the array of bytes.
    byte[] hashValue = SHhash.ComputeHash(MessageBytes);

    //Convert the Hash value array to string
    StringBuilder outputS = new StringBuilder(hashValue.Length);
    for (int i=0;i < hashValue.Length; i++) 
    {
      outputS.Append(hashValue[i].ToString("X2"));
    }
    return outputS.ToString();

}
