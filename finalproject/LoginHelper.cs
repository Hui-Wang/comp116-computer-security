using System;
using System.Data;
using System.Configuration;
using System.Collections;
using System.Web;
using System.Web.Security;
using System.Data.SqlClient;

public class LoginHelper
{
    // get roles list from database for authenticated user
    // output string will be formatted as "Role1|Role2|Role3|..."
    protected string GetRolesForUser(string uname) 
    {
        string roles = "";
        string connStr = ConfigurationManager.ConnectionStrings["MYDB"].ConnectionString;
        SqlConnection conn = new SqlConnection(connStr);

        try
        {
            conn.Open();
            SqlCommand cmd = new SqlCommand("GetUserRoles", conn);
            cmd.CommandType = CommandType.StoredProcedure;
            cmd.Parameters.Add(new SqlParameter("@Username", uname));
            SqlDataReader reader = cmd.ExecuteReader();

            ArrayList roleList = new ArrayList();
            while (reader.Read())
                roles += reader["Role"].ToString() + "|";
            if (roles != "")  
                roles = roles.Substring(0, roles.Length - 1);
            conn.Close();
        }
        catch (Exception ex)
        {
            throw ex;
        }
        finally
        {
            conn.Close();
        }
        return roles;
    }


    // Perform validation for username and password
    private string CheckUser(string uid, string pwd)
    {
        string userval = "";
        try
        {
            string sql = "select UserName from RegUsers where Username='" +
                                    uid + "'";
            Object objuid = DBFunctions.GetScalarDB(sql);
            if (objuid != null)
            {
                //-------- see if password is OK--------------
                string sqlpw = "select Password from RegUsers where Username='" +
                    uid + "'";

                Object objpw = DBFunctions.GetScalarDB(sqlpw);
                if (objpw != null)
                {
                    string pwdRecov = objpw.ToString().Replace("\0", "");
                    if (objuid.ToString().Replace("\0", "") == pwd)
                    {
                        Session["USERID"] = objuid.ToString();
                        userval = objuid.ToString();  // Username column
                    }
                }

            }
        }
        catch (Exception ex)
        {
           Console.WriteLine(ex.ToString()); 
        }
        return userval;

    }

    

    // Perform user authentication and get user roles if the authentication passes
    public bool Login(object sender, EventArgs e)
    {

        string uid, pwd;
        uid = txtUsername.Text;
        pwd = txtPassword.Text;
        string accessLevel = CheckUser(uid, pwd);
        // After user has been authenticated, get roles for the user, encrypt the role data and 
        // add it to the cookie, so that no need to read from database every time. 
        if (accessLevel != "")
        {
            Session["USERNAME"] = uid;
            Session["LOGIN"] = "NEW";

            //-----------Create authentication cookie----
            string roles = GetRolesForUser(uid);//get roles list
            FormsAuthenticationTicket authTicket
                    = new FormsAuthenticationTicket(1, uid, DateTime.Now, DateTime.Now.AddMinutes(30), false, roles);
            //  encrypt the ticket
            string encryptedTicket =
                FormsAuthentication.Encrypt(authTicket);

            // add the encrypted ticket to the cookie as data
            HttpCookie authCookie = new HttpCookie
                (FormsAuthentication.FormsCookieName, encryptedTicket);
            Response.Cookies.Add(authCookie);

            Response.Redirect(FormsAuthentication.GetRedirectUrl(uid, true));

            return true;
                
        }
        else
        {
            Console.WriteLine("Login failed ! "); 
            return false;
        }
    }

}
