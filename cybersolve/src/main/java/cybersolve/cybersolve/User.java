package cybersolve.cybersolve;

import java.awt.List;
import java.io.FileNotFoundException;
import java.sql.Connection;
import java.sql.Date;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.Scanner;

public class User {
	 
	String firstname,lastname,password,uname,username,email;

    public User(String firstname, String lastname,String username, String email,String password) {
		
    	this.firstname = firstname;
		this.lastname = lastname;
		this.username = username;
		this.email = email;
        this.password = password;
		
		
	}
    
    public User(String firstname,String lastname,String username) {
    	this.firstname = firstname;
		this.lastname = lastname;
		this.username = username;
     
    }

    public String usernamecreation() {
        String uname = firstname.concat(".").concat(lastname);
        String newUsername = uname;
        
        try (Connection c = Db.connect();
             PreparedStatement ps = c.prepareStatement("SELECT username FROM details WHERE username LIKE ?")) {
            
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
			  String query = "insert into details(firstname,lastname,username,email,password,user_type,date) values(?,?,?,?,?,?,?)";
			  String query1="select count(*) from details";
			  try(PreparedStatement ps= c.prepareStatement(query1);
			  ResultSet rs=ps.executeQuery()){
				  if(rs.next()&& rs.getInt(1)==0) {
					  usertype="Admin";
				  }
				  
			  }
			  try(PreparedStatement ps1= c.prepareStatement(query)){
				  ps1.setString(1, firstname);
				  ps1.setString(2, lastname);
				  ps1.setString(3, username);
				  ps1.setString(4, email);
				  ps1.setString(5, password);
				  ps1.setString(6, usertype);
				  ps1.setDate(7, Date.valueOf(LocalDate.now()));
				  
				  ps1.executeUpdate();
			  }
			  
			  
			  return "Your username :"+username;
			  }
			  catch(Exception e)
			  {
				    return e.getMessage();
			  }

	  }
    public boolean login(String username, String password) throws ClassNotFoundException {
    	
        String hashedPassword = PasswordEncryption.simpleHash(password);
        String query = "SELECT username FROM details WHERE password = ?";

        try (Connection c = Db.connect();
             PreparedStatement ps = c.prepareStatement(query)) {

            ps.setString(1, hashedPassword);
           

            try (ResultSet rs = ps.executeQuery()) {
                while(rs.next()) {
                	String s=rs.getString("username");
                	if(s.equals(username)) {
                		return true;
                	}
                }
            }

        } catch (SQLException e) {
//            return "Error during login: " + e.getMessage();
        }
        return false;
    }

	public User() {
		super();
	}
	
	public String checkresource(String username) throws Exception

	{

		String query = "SELECT * FROM user_resources WHERE username = ?";

        try

        {

        	Connection c = Db.connect();

        	PreparedStatement ps = c.prepareStatement(query) ;

            ps.setString(1, username);

            ResultSet resultSet = ps.executeQuery();

            if (resultSet.next()) {

                String res=resultSet.getString("resource_name");

                return res;

            }

        } catch (SQLException e) {

            return e.getMessage();

        }

		return "No resource found";

	}
 
	 public void requestRole(String requestedRole) throws Exception {
	        try (Connection conn = Db.connect()) {
	            String query = "INSERT INTO requests (username, request_type, request_value, status) VALUES (?, ?, ?, FALSE)";
	            try (PreparedStatement stmt = conn.prepareStatement(query)) {
	                stmt.setString(1, username);
	                stmt.setString(2, "Role Request");
	                stmt.setString(3, requestedRole);
	                stmt.executeUpdate();
	            }
	        } catch (SQLException e) {
	            throw new RuntimeException("Failed to request role: " + e.getMessage(), e);
	        }
	    }
	    
	    public void requestResources(String requestedRole) throws SQLException, Exception {
	        try (Connection conn = Db.connect()) {
	            // Check if the resource exists
	            String checkQuery = "SELECT COUNT(*) FROM resources WHERE resource_name = ?";
	            try (PreparedStatement checkStmt = conn.prepareStatement(checkQuery)) {
	                checkStmt.setString(1, requestedRole);
	                ResultSet rs = checkStmt.executeQuery();
	                
	                if (rs.next() && rs.getInt(1) > 0) {
	                    // Resource exists, proceed with the request
	                    String requestType = "Resource Request";
	                    String insertQuery = "INSERT INTO requests (username, request_type, request_value, status) VALUES (?, ?, ?, false)";
	                    
	                    try (PreparedStatement insertStmt = conn.prepareStatement(insertQuery)) {
	                        insertStmt.setString(1, username);
	                        insertStmt.setString(2, requestType);
	                        insertStmt.setString(3, requestedRole);
	                        insertStmt.executeUpdate();
	                    }
	                    
	                    System.out.println("Resource request submitted successfully.");
	                } else {
	                    // Resource does not exist
	                    throw new SQLException("Requested resource does not exist.");
	                }
	            }
	        } catch (SQLException e) {
	            throw new SQLException("Failed to request resource: " + e.getMessage(), e);
	        }
	    }

	   
	    
	    public void assignManager(String username) throws Exception {
	        try (Connection conn = Db.connect()) {
	            String query = "UPDATE details SET user_type = 'Manager' WHERE username = ?";
	            
	            try (PreparedStatement stmt = conn.prepareStatement(query)) {
	                stmt.setString(1, username);
	                
	                int rowsAffected = stmt.executeUpdate();
	                
	                if (rowsAffected > 0) {
	                    System.out.println("User type updated to manager successfully.");
	                } else {
	                    throw new RuntimeException("No user found with the username: " + username);
	                }
	            }
	        } catch (SQLException e) {
	            throw new RuntimeException("Failed to assign manager: " + e.getMessage(), e);
	        }
	    }

		public boolean checkpasswordconstraint(String password2) {
			// TODO Auto-generated method stub
			if(password.length()>8) {
				return true;
			}
			return false;
		}
		public ArrayList<String> fetchAllUsernames() throws ClassNotFoundException {
	        ArrayList<String> usernames = new ArrayList<>();
	        try (Connection conn = Db.connect();
	             Statement stmt = conn.createStatement();
	             ResultSet rs = stmt.executeQuery("SELECT username FROM details")) {

	            while (rs.next()) {
	                usernames.add(rs.getString("username"));
	            }
	        } catch (SQLException e) {
	            e.printStackTrace();
	        }
	        return usernames;
	    }
		
	
	
    }
    
    
    
    
