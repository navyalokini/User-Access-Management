
package cybersolve.cybersolve;

import java.io.*;
import java.sql.*;
import java.util.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.ws.rs.Consumes;
import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;



@Path("myresource")
public class MyResource {

    @GET
    @Produces(MediaType.TEXT_PLAIN)
    public String getIt() {
        return "Got it!";
    }

  
    @GET
    @Path("dbconnect")
    public String db() throws ClassNotFoundException, SQLException {
    	
        Connection c=Db.connect();
        if(c!=null) {
        	return "connection is successfull";
        }
        else
		return "not connected";
    }
    @POST
    @Path("register")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public String register(@FormParam("firstname")String firstname,@FormParam("lastname") String lastname,@FormParam("email") String email,@FormParam("password") String password,@FormParam("confirm_password") String cpassword) throws SQLException {
    	
    	User r=new User(firstname, lastname, null,email,PasswordEncryption.simpleHash(password));
    	if(!r.checkpasswordconstraint(password)) {
    		return "password must be 8 characters long ";
    	}
    	
    	if(!cpassword.equals(password))
    		return "password dont match";
    	return r.insertdata()+"<br> <a href='http://localhost:4569/cybersolve/'>Click here login</a>";
    }
    @POST

    @Path("changepassword")

    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)

    public Response updatePassword(

            @FormParam("oldpassword") String oldpassword,

            @FormParam("newpassword") String newpassword, 

            @Context HttpServletRequest request) {

    	

        oldpassword=PasswordEncryption.simpleHash(oldpassword);

        newpassword=PasswordEncryption.simpleHash(newpassword);

        HttpSession session = request.getSession();

        String username = (String) session.getAttribute("username");

        try {

            Connection conn = Db.connect();
 
            // First query: Check if the user exists and the old password matches

            String checkQuery = "SELECT COUNT(*) FROM details WHERE username = ? AND password = ?";

            PreparedStatement checkPassword = conn.prepareStatement(checkQuery);

            checkPassword.setString(1, username);

            checkPassword.setString(2, oldpassword);

            ResultSet resultSet = checkPassword.executeQuery();

            resultSet.next();

            int count = resultSet.getInt(1);
 
            if (count == 1) {

                // Second query: Update the password if the old password matches

                String updateQuery = "UPDATE details SET password = ? WHERE username = ?";

                PreparedStatement updatePassword = conn.prepareStatement(updateQuery);

                updatePassword.setString(1, newpassword);

                updatePassword.setString(2, username);

                updatePassword.executeUpdate();
 
                return Response.ok("Password changed successfully").build();

            } else {

                return Response.status(Response.Status.UNAUTHORIZED)

                        .entity("Invalid old password or username").build();

            }

        } catch (Exception e) {

            e.printStackTrace();

            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)

                    .entity("An error occurred while changing the password").build();

        }

    }
 
    @POST
    @Path("login")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public void login(@FormParam("username") String username, @FormParam("password") String password, @Context HttpServletResponse response,@Context HttpServletRequest request
    		 ) throws IOException {
        Connection c = null;
        PreparedStatement ps = null;
        ResultSet rs = null;

        try {
            User ob = new User();
           

      	  HttpSession session = request.getSession();

            session.setAttribute("username", (username));
       
            if (ob.login(username, password)) {
                c = Db.connect();
                String q = "SELECT * FROM details WHERE username = ?";
                ps = c.prepareStatement(q);
                ps.setString(1, username);
                rs = ps.executeQuery();

                if (rs.next()) {
                    String userType = rs.getString("user_type");

                    if ("Admin".equals(userType)) {
                        response.sendRedirect("/cybersolve/Admin.html?username=" +username);
                    } else if ("Manager".equals(userType)) {
                        response.sendRedirect("/cybersolve/Manager.html?username="+username);
                    } else {
                        response.sendRedirect("/cybersolve/User.html?username="+username);
                    }
                } else {
                    response.sendRedirect("/cybersolve/?message=User not found");
                }
            } else {
                response.sendRedirect("/cybersolve/?message=Invalid credentials");
            }
        } catch (Exception e) {
            response.sendRedirect("/cybersolve/?message=Cannot login");
        } finally {
            // Close resources
            try {
                if (rs != null) rs.close();
                if (ps != null) ps.close();
                if (c != null) c.close();
            } catch (SQLException e) {
                e.printStackTrace();
            }
        }
    }
    @POST

    @Path("forgot-password")

    @Consumes("application/x-www-form-urlencoded")

    public Response forgetPassword(

        @FormParam("username") String username,

        @FormParam("email") String email,

        @FormParam("new-password") String newPassword) throws ClassNotFoundException {

    	User u = new User();

    	newPassword=PasswordEncryption.simpleHash(newPassword);

        Connection conn = null;

        PreparedStatement checkUserStmt = null;

        PreparedStatement updatePasswordStmt = null;
 
        try {

            // Establish database connection

            conn = Db.connect();
 
            // Check if the username and email are valid

            String checkUserQuery = "SELECT * FROM details WHERE username = ? AND email = ?";

            checkUserStmt = conn.prepareStatement(checkUserQuery);

            checkUserStmt.setString(1, username);

            checkUserStmt.setString(2, email);
 
            ResultSet rs = checkUserStmt.executeQuery();
 
            if (rs.next()) {

                // Username and email are valid, update the password

                String updatePasswordQuery = "UPDATE details SET password = ? WHERE username = ?";

                updatePasswordStmt = conn.prepareStatement(updatePasswordQuery);

                updatePasswordStmt.setString(1, newPassword);  // Note: Hash the password before storing in production

                updatePasswordStmt.setString(2, username);

                updatePasswordStmt.executeUpdate();
 
                return Response.ok("Password updated successfully.").build();

            } else {

                // Username and email are not valid

                return Response.status(Response.Status.BAD_REQUEST)

                               .entity("Invalid username or email.").build();

            }
 
        } catch (SQLException e) {

            e.printStackTrace();

            return Response.serverError().entity("Database error: " + e.getMessage()).build();

        } finally {

            // Close resources in finally block to ensure they're always closed

            try {

                if (checkUserStmt != null) checkUserStmt.close();

                if (updatePasswordStmt != null) updatePasswordStmt.close();

                if (conn != null) conn.close();

            } catch (SQLException e) {

                e.printStackTrace();

            }

        }

    }
 
    
    @POST
    @Path("logout")
    
    public Response logout(@Context HttpServletRequest request) {

        HttpSession session = request.getSession(false);
 
        if (session != null) {
 
            session.invalidate();  // Invalidate the session
 
        }
 
        return Response.ok().build();
 
    }
 
    @POST
    @Path("requestRole")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public void requestRole(@FormParam("requestedRole") String requestedRole,
                            @Context HttpServletRequest request,
                            @Context HttpServletResponse response) throws IOException {
        try {
            HttpSession session = request.getSession();
            String username = (String) session.getAttribute("username");

            if (username != null) {
                User ob = new User(null, null, username,null, null);
                ob.requestRole(requestedRole);
                response.sendRedirect("/cybersolve/roleRequestSuccess.jsp");
            } else {
                response.sendRedirect("/cybersolve/?message=Session expired, please login again.");
            }
        } catch (Exception e) {
            response.sendRedirect("/cybersolve/?message=Cannot process request");
        }
    }
    @POST
    @Path("requestResources")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public void requestResources(@FormParam("resourceName")String requestResources,
    		@Context HttpServletRequest request,
            @Context HttpServletResponse response) throws IOException {
    	try {
            HttpSession session = request.getSession();
            String username = (String) session.getAttribute("username");
            if (username != null) {
            	User ob = new User(null, null, username,null, null);
            	ob.requestResources(requestResources);
                response.sendRedirect("/cybersolve/roleRequestSuccess.jsp");

            } 
    	else {
                response.sendRedirect("/cybersolve/?message=Session expired, please login again.");
            }
    	}catch (Exception e) {
                response.sendRedirect("/cybersolve/?message=Resource doesnot Exists");
            }
    }
    @GET
    @Path("requests")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getRequests() throws Exception {
        List<Request> requests = new ArrayList<>();
        try (Connection conn = Db.connect()) {
            String query = "SELECT * FROM requests WHERE status = 0";
            try (PreparedStatement stmt = conn.prepareStatement(query);
                 ResultSet rs = stmt.executeQuery()) {
                while (rs.next()) {
                    String username = rs.getString("username");
                    String requestType = rs.getString("request_type");
                    String requestValue = rs.getString("request_value");
                    boolean approved = rs.getBoolean("accepted");
                    requests.add(new Request(username, requestType, requestValue, approved));
                }
            }
        } catch (SQLException e) {
            return Response.serverError().entity("Error fetching requests: " + e.getMessage()).build();
        }
        return Response.ok(requests).build();
    }
    
    @POST
    @Path("request/accept")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public Response acceptRequest(@FormParam("username") String username,
                                  @FormParam("requestType") String requestType,
                                  @FormParam("requestValue") String requestValue) throws Exception {
        try (Connection conn = Db.connect()) {
            String updateQuery = "UPDATE requests SET status = 1, accepted= 1 WHERE username = ? AND request_type = ? AND request_value = ?";
            try (PreparedStatement stmt = conn.prepareStatement(updateQuery)) {
                stmt.setString(1, username);
                stmt.setString(2, requestType);
                stmt.setString(3, requestValue);
                stmt.executeUpdate();
                
                // Additional logic for Role Request
                if (requestType.equals("Role Request")) {
                    String updateDetailsQuery = "UPDATE details SET user_type = ? WHERE username = ?";
                    try (PreparedStatement updateStmt = conn.prepareStatement(updateDetailsQuery)) {
                        updateStmt.setString(1, requestValue);
                        updateStmt.setString(2, username);
                        updateStmt.executeUpdate();
                    }
                }

                // Additional logic for Resource Request
                if (requestType.equals("Resource Request")) {
                    String insertQuery = "INSERT INTO user_resources (username, resource_name) VALUES (?, ?)";
                    try (PreparedStatement insertStmt = conn.prepareStatement(insertQuery)) {
                        insertStmt.setString(1, username);
                        insertStmt.setString(2, requestValue);
                        insertStmt.executeUpdate();
                    }
                }
            }
        } catch (SQLException e) {
            return Response.serverError().entity("Error accepting request: " + e.getMessage()).build();
        }
        return Response.ok("Request accepted").build();
    }

    @POST
    @Path("request/reject")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public Response rejectRequest(@FormParam("username") String username,
                                  @FormParam("requestType") String requestType,
                                  @FormParam("requestValue") String requestValue) throws Exception {
        try (Connection conn = Db.connect()) {
            String updateQuery = "UPDATE requests SET status = 1, accepted = 0 WHERE username = ? AND request_type = ? AND request_value = ?";
            try (PreparedStatement stmt = conn.prepareStatement(updateQuery)) {
                stmt.setString(1, username);
                stmt.setString(2, requestType);
                stmt.setString(3, requestValue);
                stmt.executeUpdate();
            }
        } catch (SQLException e) {
            return Response.serverError().entity("Error rejecting request: " + e.getMessage()).build();
        }
        return Response.ok("Request rejected").build();
    }
    @GET
    @Path("resources")
    public Response getResources() throws Exception {
        List<Resource> resources = new ArrayList<>();

        try (Connection conn = Db.connect()) {
            String query = "SELECT resource_name FROM resources";
            try (Statement stmt = conn.createStatement();
                 ResultSet rs = stmt.executeQuery(query)) {

                while (rs.next()) {
                    Resource resource = new Resource();
                    resource.setResourceName(rs.getString("resource_name"));
                    resources.add(resource);
                }
            }
        } catch (SQLException e) {
            return Response.serverError().entity("Error fetching resources: " + e.getMessage()).build();
        }

        return Response.ok(resources).build();
    }

    @POST
    @Path("resource/delete")
    @Consumes("application/x-www-form-urlencoded")
    public Response deleteResource(@FormParam("resourceName") String resourceName) throws Exception {
        try (Connection conn = Db.connect()) {
            conn.setAutoCommit(false);
            
            try {
                String deleteReferencesQuery = "DELETE FROM user_resources WHERE resource_name = ?";
                try (PreparedStatement stmt = conn.prepareStatement(deleteReferencesQuery)) {
                    stmt.setString(1, resourceName);
                    stmt.executeUpdate();
                }

                String deleteResourceQuery = "DELETE FROM resources WHERE resource_name = ?";
                try (PreparedStatement stmt = conn.prepareStatement(deleteResourceQuery)) {
                    stmt.setString(1, resourceName);
                    int rowsAffected = stmt.executeUpdate();
                    
                    if (rowsAffected > 0) {
                        conn.commit();
                        return Response.ok("Resource deleted successfully").build();
                    } else {
                        conn.rollback();
                        return Response.status(Response.Status.NOT_FOUND).entity("Resource not found").build();
                    }
                }
            } catch (SQLException e) {
                conn.rollback();
                return Response.serverError().entity("Error deleting resource: " + e.getMessage()).build();
            }
        } catch (SQLException e) {
            return Response.serverError().entity("Database connection error: " + e.getMessage()).build();
        }
    }
    
    @GET
    @Path("userresources")
    public Response getUserResources() throws Exception {
        List<UserResource> userResources = new ArrayList<>();
        
        try (Connection conn =Db.connect()) {
            String query = "SELECT username, resource_name FROM user_resources";
            try (Statement stmt = conn.createStatement();
                 ResultSet rs = stmt.executeQuery(query)) {

                while (rs.next()) {
                    UserResource ur = new UserResource();
                    ur.setUsername(rs.getString("username"));
                    ur.setResourceName(rs.getString("resource_name"));
                    userResources.add(ur);
                }
            }
        } catch (SQLException e) {
            return Response.serverError().entity("Error fetching user resources: " + e.getMessage()).build();
        }

        return Response.ok(userResources).build();
    }

    @POST
    @Path("resource/remove")
    @Consumes("application/x-www-form-urlencoded")
    public Response removeResourceFromUser(@FormParam("username") String username,
                                           @FormParam("resourceName") String resourceName) throws Exception {
        try (Connection conn = Db.connect()) {
            String deleteQuery = "DELETE FROM user_resources WHERE username = ? AND resource_name = ?";
            try (PreparedStatement stmt = conn.prepareStatement(deleteQuery)) {
                stmt.setString(1, username);
                stmt.setString(2, resourceName);
                int rowsAffected = stmt.executeUpdate();

                if (rowsAffected > 0) {
                    return Response.ok("Resource removed successfully").build();
                } else {
                    return Response.status(Response.Status.NOT_FOUND).entity("Resource or user not found").build();
                }
            }
        } catch (SQLException e) {
            return Response.serverError().entity("Error removing resource: " + e.getMessage()).build();
        }
    }
    
    @POST
    @Path("checkresources")
    @Consumes("application/x-www-form-urlencoded")
    public Response checkResources(@FormParam("username") String username) throws Exception {
        List<String> resources = new ArrayList<>();
        
        try (Connection conn = Db.connect()) {
            String query = "SELECT resource_name FROM user_resources WHERE username = ?";
            try (PreparedStatement stmt = conn.prepareStatement(query)) {
                stmt.setString(1, username);
                try (ResultSet rs = stmt.executeQuery()) {
                    while (rs.next()) {
                        resources.add(rs.getString("resource_name"));
                    }
                }
            }
        } catch (SQLException e) {
            return Response.serverError().entity("Error fetching resources: " + e.getMessage()).build();
        }

        StringBuilder responseHtml = new StringBuilder("<h3>Resources for user: " + username + "</h3>");
        if (resources.isEmpty()) {
            responseHtml.append("<p>No resources found for the user.</p>");
        } else {
            responseHtml.append("<ul>");
            for (String resource : resources) {
                responseHtml.append("<li>").append(resource).append("</li>");
            }
            responseHtml.append("</ul>");
        }

        // Return HTML content to be displayed on the same page
        return Response.ok(responseHtml.toString()).build();
    }
    
    @POST
    @Path("checkusers")
    @Consumes("application/x-www-form-urlencoded")
    public Response checkUsers(@FormParam("resourceName") String resourceName) throws Exception {
        List<String> users = new ArrayList<>();
        
        try (Connection conn = Db.connect()) {
            String query = "SELECT username FROM user_resources WHERE resource_name = ?";
            try (PreparedStatement stmt = conn.prepareStatement(query)) {
                stmt.setString(1, resourceName);
                try (ResultSet rs = stmt.executeQuery()) {
                    while (rs.next()) {
                        users.add(rs.getString("username"));
                    }
                }
            }
        } catch (SQLException e) {
            return Response.serverError().entity("Error fetching users: " + e.getMessage()).build();
        }

        StringBuilder responseHtml = new StringBuilder("<h3>Users with resource: " + resourceName + "</h3>");
        if (users.isEmpty()) {
            responseHtml.append("<p>No users found with the specified resource.</p>");
        } else {
            responseHtml.append("<ul>");
            for (String user : users) {
                responseHtml.append("<li>").append(user).append("</li>");
            }
            responseHtml.append("</ul>");
        }

        // Return HTML content to be displayed on the same page
        return Response.ok(responseHtml.toString()).build();
    }
    @GET

    @Path("listcheck")

    public Response listgen(@Context HttpServletRequest request) throws IOException {

        List<String> list1 = new ArrayList<>(); // List to store results of q1

        List<String> list2 = new ArrayList<>(); // List to store results of q2

        List<String> onlyInList1 = new ArrayList<>(); // List to store resources only in list1

        List<String> pendingResources = new ArrayList<>(); // List to store resources with pending requests
 
        try {

            Connection conn = Db.connect();

            HttpSession session = request.getSession();

            String username = (String) session.getAttribute("username");
 
            // Query 1: Get all resources

            String q1 = "SELECT resource_name FROM resources";

            PreparedStatement ps1 = conn.prepareStatement(q1);

            ResultSet rs1 = ps1.executeQuery();
 
            while (rs1.next()) {

                list1.add(rs1.getString("resource_name"));

            }
 
            // Query 2: Get resources already assigned to the user

            String q2 = "SELECT resource_name FROM user_resources WHERE username=?";

            PreparedStatement ps2 = conn.prepareStatement(q2);

            ps2.setString(1, username);

            ResultSet rs2 = ps2.executeQuery();
 
            while (rs2.next()) {

                list2.add(rs2.getString("resource_name"));

            }
 
            // Query 3: Get resources with pending requests by the user

            String q3 = "SELECT request_value FROM requests WHERE username=? AND request_type='Resource Request' AND status=0 AND accepted=0";

            PreparedStatement ps3 = conn.prepareStatement(q3);

            ps3.setString(1, username);

            ResultSet rs3 = ps3.executeQuery();
 
            while (rs3.next()) {

                pendingResources.add(rs3.getString("request_value"));

            }
 
            // Create a Set for list2 for efficient lookups

            Set<String> set2 = new HashSet<>(list2);
 
            // Find resources in list1 but not in list2

            for (String resource : list1) {

                if (!set2.contains(resource)) {

                    onlyInList1.add(resource);

                }

            }
 
            // Remove resources from onlyInList1 if they have pending requests

            onlyInList1.removeAll(pendingResources);
 
            // Close resources

            rs1.close();

            ps1.close();

            rs2.close();

            ps2.close();

            rs3.close();

            ps3.close();

            conn.close();

        } catch (Exception e) {

            e.printStackTrace(); // Log the exception (or handle it accordingly)

            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity("Error processing request").build();

        }
 
        // Return the lists as part of the response

        return Response.ok(onlyInList1).build();

    }
 
    
    @GET

    @Path("checkapprovals")

    public Response checkApprovals(@Context HttpServletRequest request) throws Exception {

        Connection conn = null;

        PreparedStatement ps1 = null;

        ResultSet rs1 = null;

        StringBuilder result = new StringBuilder();
 
        try {

            conn = Db.connect();

            String q1 = "SELECT username, request_type, request_value, status, accepted FROM requests";

            ps1 = conn.prepareStatement(q1);

            rs1 = ps1.executeQuery();
 
            // Build a JSON-like structure using StringBuilder

            result.append("[");  // Start of JSON array
 
            while (rs1.next()) {

                if (result.length() > 1) {

                    result.append(",");  // Separate objects with commas

                }
 
                String username = rs1.getString("username");

                String requestType = rs1.getString("request_type");

                String requestValue = rs1.getString("request_value");

                int status = rs1.getInt("status");

                int approved = rs1.getInt("accepted");

                String requestStatus;
 
                // Determine the request status based on the conditions

                if (status == 0 && approved == 0) {

                    requestStatus = "Pending";

                } else if (status == 1 && approved == 1) {

                    requestStatus = "Accepted";

                } else if (status == 1 && approved == 0) {

                    requestStatus = "Rejected";

                } else {

                    requestStatus = "Unknown";

                }
 
                // Add the JSON object for this record

                result.append("{")

                      .append("\"username\":\"").append(username).append("\",")

                      .append("\"request_type\":\"").append(requestType).append("\",")

                      .append("\"request_value\":\"").append(requestValue).append("\",")

                      .append("\"request_status\":\"").append(requestStatus).append("\"")

                      .append("}");

            }
 
            result.append("]");  // End of JSON array
 
        } catch (Exception e) {

            e.printStackTrace();

            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)

                           .entity("Error fetching approvals").build();

        } finally {

            // Clean up resources

            if (rs1 != null) rs1.close();

            if (ps1 != null) ps1.close();

            if (conn != null) conn.close();

        }
 
        return Response.ok(result.toString()).build();

    }
 
    
    @GET

    @Path("checkmyapprovals")

    public Response checkMyApprovals(@Context HttpServletRequest request) throws Exception {

        Connection conn = null;

        PreparedStatement ps1 = null;

        ResultSet rs1 = null;

        StringBuilder result = new StringBuilder();
        HttpSession session = request.getSession(false); // Use false to avoid creating a new session
        if (session == null) {
            return Response.status(Response.Status.UNAUTHORIZED).entity("Session not found").build();
        }
        String username1 = (String) session.getAttribute("username"); // Ensure the session attribute name is correct
        if (username1 == null) {
            return Response.status(Response.Status.UNAUTHORIZED).entity("Manager ID not found").build();
        }
 
        try {

            conn = Db.connect();

            String q1 = "SELECT username, request_type, request_value, status, accepted FROM requests where username = '"+username1+"' ";
            
            ps1 = conn.prepareStatement(q1);
            
            rs1 = ps1.executeQuery();
 
            // Build a JSON-like structure using StringBuilder

            result.append("[");  // Start of JSON array
 
            while (rs1.next()) {

                if (result.length() > 1) {

                    result.append(",");  // Separate objects with commas

                }
 
                String username = rs1.getString("username");

                String requestType = rs1.getString("request_type");

                String requestValue = rs1.getString("request_value");

                int status = rs1.getInt("status");

                int approved = rs1.getInt("accepted");

                String requestStatus;
 
                // Determine the request status based on the conditions

                if (status == 0 && approved == 0) {

                    requestStatus = "Pending";

                } else if (status == 1 && approved == 1) {

                    requestStatus = "Accepted";

                } else if (status == 1 && approved == 0) {

                    requestStatus = "Rejected";

                } else {

                    requestStatus = "Unknown";

                }
 
                // Add the JSON object for this record

                result.append("{")

                      .append("\"username\":\"").append(username).append("\",")

                      .append("\"request_type\":\"").append(requestType).append("\",")

                      .append("\"request_value\":\"").append(requestValue).append("\",")

                      .append("\"request_status\":\"").append(requestStatus).append("\"")

                      .append("}");

            }
 
            result.append("]");  // End of JSON array
 
        } catch (Exception e) {

            e.printStackTrace();

            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)

                           .entity("Error fetching approvals").build();

        } finally {

            // Clean up resources

            if (rs1 != null) rs1.close();

            if (ps1 != null) ps1.close();

            if (conn != null) conn.close();

        }
 
        return Response.ok(result.toString()).build();

    }
 

    
    @GET
    @Path("users")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getUsers() throws Exception {
        try (Connection conn = Db.connect()) {
            String query = "SELECT firstname, lastname, username, managerID FROM details";
            try (PreparedStatement stmt = conn.prepareStatement(query);
                 ResultSet rs = stmt.executeQuery()) {

                List<User> users = new ArrayList<>();
                while (rs.next()) {
                    String firstname = rs.getString("firstname");
                    String lastname = rs.getString("lastname");
                    String username = rs.getString("username");
                    String email = rs.getString("email");
                    String managerID = rs.getString("managerID");
                    
                    User user = new User(firstname, lastname, username, email,managerID);
                    users.add(user);
                }
                
                return Response.ok(users.toString()).build();
            }
        } catch (SQLException e) {
            return Response.serverError().entity("Database error: " + e.getMessage()).build();
        }
    }
    @POST
    @Path("addUser")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.TEXT_HTML)
    public void addUser(@FormParam("firstname") String firstname,
                         @FormParam("lastname") String lastname,
                         @FormParam("email") String email,
                         @Context HttpServletResponse response) throws IOException {
        
        try {
        	String password = firstname+lastname;
        	String username="";
        	
            User ob = new User(firstname, lastname, PasswordEncryption.simpleHash(password));
            username=ob.usernamecreation();
            ob.insertdata();
            
            response.sendRedirect("/cybersolve/addUserSuccess.jsp?message=User Added successful&username=" + username);
        } catch (Exception e) {
            response.sendRedirect("/cybersolve/userAddFailure.jsp?message=Failed To add User: " + e.getMessage());
        }
    }
    
  
    @GET

    @Path("allusers")

    @Produces(MediaType.APPLICATION_JSON)

    public Response getAllUsers() throws ClassNotFoundException {

        List<Map<String, String>> users = new ArrayList<>();
 
        try (Connection conn = Db.connect()) {

            String query = "SELECT username FROM details where user_type!='Admin'";

            try (PreparedStatement stmt = conn.prepareStatement(query);

                 ResultSet rs = stmt.executeQuery()) {
 
                while (rs.next()) {

                    Map<String, String> user = new HashMap<>();

                    user.put("username", rs.getString("username"));

                    users.add(user);

                }

            }

        } catch (SQLException e) {

            return Response.serverError().entity("Database error: " + e.getMessage()).build();

        }
 
        return Response.ok(users).build();

    }
 
    @POST

    @Path("removeuser")

    @Consumes("application/x-www-form-urlencoded")

    public Response removeUser(@FormParam("user") String username) throws Exception {

        Connection conn = null;

        PreparedStatement deleteUserResourcesStmt = null;

        PreparedStatement deleteUserRequestsStmt = null;

        PreparedStatement deleteUserStmt = null;
 
        try {

            conn = Db.connect();

            conn.setAutoCommit(false); // Start transaction
 
            // Step 1: Remove the user's attached resources from user_resources table

            String deleteUserResourcesQuery = "DELETE FROM user_resources WHERE username = ?";

            deleteUserResourcesStmt = conn.prepareStatement(deleteUserResourcesQuery);

            deleteUserResourcesStmt.setString(1, username);

            deleteUserResourcesStmt.executeUpdate();
 
            // Step 2: Remove the user's pending requests from requests table

            String deleteUserRequestsQuery = "DELETE FROM requests WHERE username = ? AND status = 0 AND accepted = 0";

            deleteUserRequestsStmt = conn.prepareStatement(deleteUserRequestsQuery);

            deleteUserRequestsStmt.setString(1, username);

            deleteUserRequestsStmt.executeUpdate();
 
            // Step 3: Remove the user from the users table

            String deleteUserQuery = "DELETE FROM details WHERE username = ?";

            deleteUserStmt = conn.prepareStatement(deleteUserQuery);

            deleteUserStmt.setString(1, username);

            deleteUserStmt.executeUpdate();
 
            // Commit the transaction

            conn.commit();
 
            return Response.ok("User and associated records removed successfully.").build();

        } catch (SQLException e) {

            if (conn != null) {

                try {

                    conn.rollback(); // Rollback in case of error

                } catch (SQLException ex) {

                    ex.printStackTrace();

                }

            }

            return Response.serverError().entity("Failed to remove user: " + e.getMessage()).build();

        } finally {

            // Close resources in the finally block to ensure they're always closed

            if (deleteUserResourcesStmt != null) {

                try {

                    deleteUserResourcesStmt.close();

                } catch (SQLException e) {

                    e.printStackTrace();

                }

            }

            if (deleteUserRequestsStmt != null) {

                try {

                    deleteUserRequestsStmt.close();

                } catch (SQLException e) {

                    e.printStackTrace();

                }

            }

            if (deleteUserStmt != null) {

                try {

                    deleteUserStmt.close();

                } catch (SQLException e) {

                    e.printStackTrace();

                }

            }

            if (conn != null) {

                try {

                    conn.close();

                } catch (SQLException e) {

                    e.printStackTrace();

                }

            }

        }

    }
 


    @POST
    @Path("updateuser")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public Response updateUser(
            @FormParam("username") String oldUsername,
            @FormParam("firstname") String firstname,
            @FormParam("lastname") String lastname) throws Exception {

        Connection conn = null;
        PreparedStatement updateDetailsStmt = null;
        PreparedStatement updateUserResourcesStmt = null;
        PreparedStatement updateRequestsStmt = null;

        try {
            conn = Db.connect();
            conn.setAutoCommit(false); // Start transaction

            // Generate a new username based on the updated firstname and lastname
            User user = new User(firstname, lastname, oldUsername);
            String newUsername = user.usernamecreation();

            // Update the username, firstname, and lastname in the details table
            String updateDetailsQuery = "UPDATE details SET username = ?, firstname = ?, lastname = ? WHERE username = ?";
            updateDetailsStmt = conn.prepareStatement(updateDetailsQuery);
            updateDetailsStmt.setString(1, newUsername);
            updateDetailsStmt.setString(2, firstname);
            updateDetailsStmt.setString(3, lastname);
            updateDetailsStmt.setString(4, oldUsername);
            updateDetailsStmt.executeUpdate();

            // Update the username in the user_resources table
            String updateUserResourcesQuery = "UPDATE user_resources SET username = ? WHERE username = ?";
            updateUserResourcesStmt = conn.prepareStatement(updateUserResourcesQuery);
            updateUserResourcesStmt.setString(1, newUsername);
            updateUserResourcesStmt.setString(2, oldUsername);
            updateUserResourcesStmt.executeUpdate();

            // Update the username in the requests table
            String updateRequestsQuery = "UPDATE requests SET username = ? WHERE username = ?";
            updateRequestsStmt = conn.prepareStatement(updateRequestsQuery);
            updateRequestsStmt.setString(1, newUsername);
            updateRequestsStmt.setString(2, oldUsername);
            updateRequestsStmt.executeUpdate();

            // Commit the transaction
            conn.commit();

            return Response.ok("User updated successfully. New username: " + newUsername).build();
        } catch (SQLException e) {
            if (conn != null) {
                try {
                    conn.rollback(); // Rollback in case of error
                } catch (SQLException ex) {
                    ex.printStackTrace();
                }
            }
            return Response.serverError().entity("Failed to update user: " + e.getMessage()).build();
        } finally {
            // Close resources in the finally block to ensure they're always closed
            if (updateDetailsStmt != null) {
                try {
                    updateDetailsStmt.close();
                } catch (SQLException e) {
                    e.printStackTrace();
                }
            }
            if (updateUserResourcesStmt != null) {
                try {
                    updateUserResourcesStmt.close();
                } catch (SQLException e) {
                    e.printStackTrace();
                }
            }
            if (updateRequestsStmt != null) {
                try {
                    updateRequestsStmt.close();
                } catch (SQLException e) {
                    e.printStackTrace();
                }
            }
            if (conn != null) {
                try {
                    conn.close();
                } catch (SQLException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    
    @POST
    @Path("addresource")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public Response addResource(@FormParam("resourceName") String resourceName) throws Exception {
    	
        String insertResourceQuery = "INSERT INTO resources (resource_name) VALUES (?)";

        try (Connection conn = Db.connect();
             PreparedStatement stmt = conn.prepareStatement(insertResourceQuery)) {

            stmt.setString(1, resourceName);
            int rowsAffected = stmt.executeUpdate();

            if (rowsAffected > 0) {
                return Response.ok("Resource added successfully.").build();
            } else {
                return Response.serverError().entity("Failed to add resource.").build();
            }

        } catch (SQLException e) {
            return Response.serverError().entity("Database error: " + e.getMessage()).build();
        }
    }

    @GET
    @Path("/showTeam")
    @Produces(MediaType.APPLICATION_JSON)
    public Response showTeam(@Context HttpServletRequest request) throws Exception {
        HttpSession session = request.getSession(false); // Use false to avoid creating a new session
        if (session == null) {
            return Response.status(Response.Status.UNAUTHORIZED).entity("Session not found").build();
        }
        
        String managerID = (String) session.getAttribute("username"); // Ensure the session attribute name is correct
        if (managerID == null) {
            return Response.status(Response.Status.UNAUTHORIZED).entity("Manager ID not found").build();
        }
        
        List<String> teamMembers = getTeamMembersByManagerID(managerID);
        return Response.ok(teamMembers).build();
    }

    private List<String> getTeamMembersByManagerID(String managerID) throws Exception {
        List<String> teamMembers = new ArrayList<>();
        String query = "SELECT username FROM details WHERE managerID = ?";
        try (Connection conn = Db.connect();
             PreparedStatement stmt = conn.prepareStatement(query)) {
            stmt.setString(1, managerID);
            try (ResultSet rs = stmt.executeQuery()) {
                while (rs.next()) {
                    teamMembers.add(rs.getString("username"));
                }
            }
        } catch (SQLException e) {
            e.printStackTrace(); // Consider better error handling here
        }
        return teamMembers;
    }

    @GET
    @Path("/getNullUsers")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getNullUsers(@Context HttpServletRequest request) throws Exception {
        HttpSession session = request.getSession(false); // Use false to avoid creating a new session
        if (session == null) {
            return Response.status(Response.Status.UNAUTHORIZED).entity("Session not found").build();
        }
        
        String managerID = (String) session.getAttribute("username"); // Ensure the session attribute name is correct
        if (managerID == null) {
            return Response.status(Response.Status.UNAUTHORIZED).entity("Manager ID not found").build();
        }
        
        List<String> teamMembers = getAllNullUsers();
        return Response.ok(teamMembers).build();
    }
    
    private List<String> getAllNullUsers() throws Exception {
        List<String> teamMembers = new ArrayList<>();
        String type = "user";
        String query = "SELECT username FROM details WHERE managerID IS NULL and user_type = ?";
        try (Connection conn = Db.connect();
             PreparedStatement stmt = conn.prepareStatement(query)) {
            stmt.setString(1, type);
            try (ResultSet rs = stmt.executeQuery()) {
                while (rs.next()) {
                    teamMembers.add(rs.getString("username"));
                }
            }
        } catch (SQLException e) {
            e.printStackTrace(); 
        }
        return teamMembers;
    }
    
    
    
    
    @POST
    @Path("/addToTeam")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public Response addToTeam(@FormParam("username") String username,@Context HttpServletRequest request) throws Exception {
    	HttpSession session = request.getSession(false); // Use false to avoid creating a new session
        if (session == null) {
            return Response.status(Response.Status.UNAUTHORIZED).entity("Session not found").build();
        }
        
        String managerID = (String) session.getAttribute("username"); // Ensure the session attribute name is correct
        if (managerID == null) {
            return Response.status(Response.Status.UNAUTHORIZED).entity("Manager ID not found").build();
        }
        String updateQuery = "UPDATE details SET managerID = ? WHERE username = ?";

        try (Connection conn = Db.connect();
             PreparedStatement stmt = conn.prepareStatement(updateQuery)) {

            stmt.setString(1, managerID);
            stmt.setString(2, username);
            int rowsAffected = stmt.executeUpdate();

            if (rowsAffected > 0) {
                return Response.ok("User added to team successfully.").build();
            } else {
                return Response.serverError().entity("Failed to add user to team.").build();
            }

        } catch (SQLException e) {
            return Response.serverError().entity("Database error: " + e.getMessage()).build();
        }
    }
    
    
    @GET

    @Path("/getManagerResources")

    @Produces(MediaType.APPLICATION_JSON)

    public Response getManagerResources(@Context HttpServletRequest request) throws Exception {

        HttpSession session = request.getSession(false); // Use false to avoid creating a new session

        if (session == null) {

            return Response.status(Response.Status.UNAUTHORIZED).entity("Session not found").build();

        }

        String managerID = (String) session.getAttribute("username"); // Ensure the session attribute name is correct

        if (managerID == null) {

            return Response.status(Response.Status.UNAUTHORIZED).entity("Manager ID not found").build();

        }

        List<String> resources = getAllManagerResources(managerID);

        return Response.ok(resources).build();

    }
 
    private List<String> getAllManagerResources(String managerID) throws Exception {

        List<String> resources = new ArrayList<>();

        // Update the query to fetch resources based on the managerID

        String query = "SELECT resource_name FROM user_resources WHERE username = ?";
        System.out.println(managerID);

        try (Connection conn = Db.connect();

             PreparedStatement stmt = conn.prepareStatement(query)) {

            stmt.setString(1, managerID);

            try (ResultSet rs = stmt.executeQuery()) {

                while (rs.next()) {

                    resources.add(rs.getString("resource_name")); // Fetch the correct column

                }
  
            }

        } catch (SQLException e) {

            e.printStackTrace();

        }
         System.out.println(resources.toString());
        return resources;

    }

 
    
   

    @POST
    @Path("resourceRemove")
    @Consumes("application/x-www-form-urlencoded")
    public Response removeResourceFromManager(@Context HttpServletRequest request,
                                           @FormParam("resourceName") String resourceName) throws Exception   {
        try (Connection conn = Db.connect()) {
        	HttpSession session = request.getSession(false); // Use false to avoid creating a new session
            if (session == null) {
                return Response.status(Response.Status.UNAUTHORIZED).entity("Session not found").build();
            }
            
            String managerID = (String) session.getAttribute("username"); // Ensure the session attribute name is correct
            if (managerID == null) {
                return Response.status(Response.Status.UNAUTHORIZED).entity("Manager ID not found").build();
            }
            String deleteQuery = "DELETE FROM user_resources WHERE username = ? AND resource_name = ?";
            try (PreparedStatement stmt = conn.prepareStatement(deleteQuery)) {
                stmt.setString(1, managerID);
                stmt.setString(2, resourceName);
                int rowsAffected = stmt.executeUpdate();

                if (rowsAffected > 0) {
                    return Response.ok("Resource removed successfully").build();
                } else {
                    return Response.status(Response.Status.NOT_FOUND).entity("Resource or user not found").build();
                }
            }
        } catch (SQLException e) {
            return Response.serverError().entity("Error removing resource: " + e.getMessage()).build();
        }
    }
 
   
   


	
    
}
