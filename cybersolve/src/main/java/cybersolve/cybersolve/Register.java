package cybersolve.cybersolve;


import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;



public class Register {

	String firstname,lastname,password,uname;

    public Register(String firstname, String lastname, String password) {
		super();
		this.firstname = firstname;
		this.lastname = lastname;
		this.password = password;
		
	}

    public String usernamecreation() {
        String uname = firstname.concat(".").concat(lastname);
        String newUsername = uname;
        
        try (Connection c = Db.connect();
             PreparedStatement ps = c.prepareStatement("SELECT username FROM user WHERE username LIKE ?")) {
            
            int count = 0;
            boolean usernameExists = true;
            
            // Check if the initial username exists
            while (usernameExists) {
                ps.setString(1, newUsername + "%");
                try (ResultSet rs = ps.executeQuery()) {
                    count = 0;
                    while (rs.next()) {
                        count++;
                    }
                }
                
                // If count is greater than 0, it means username exists
                if (count == 0) {
                    usernameExists = false;
                } else {
                    newUsername = uname + count;
                }
            }
            
        } catch (Exception e) {
            return e.getMessage();
        }
        
        return newUsername;
    }

    public String insertdata() throws SQLException
	  {
		try {
			  Connection c = Db.connect();
			  Statement st = c.createStatement();
			  String username=usernamecreation();
			  String usertype="user";
			  String query = "insert into user(firstname,lastname,password,username,user_type) values(?,?,?,?,?)";
			  String query1="select count(*) from user";
			  try(PreparedStatement ps= c.prepareStatement(query1);
			  ResultSet rs=ps.executeQuery()){
				  if(rs.next()&& rs.getInt(1)==0) {
					  usertype="admin";
				  }
				  
			  }
			  try(PreparedStatement ps1= c.prepareStatement(query)){
				  ps1.setString(1, firstname);
				  ps1.setString(2, lastname);
				  ps1.setString(3, password);
				  ps1.setString(4, username);
				  ps1.setString(5, usertype);
				  ps1.executeUpdate();
			  }
			  
			  
			  return "New Data Added on Name:"+firstname;
			  }
			  catch(Exception e)
			  {
				    return e.getMessage();
			  }

	  }
    


}

