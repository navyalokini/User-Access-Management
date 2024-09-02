package cybersolve.cybersolve;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

public class Db {
	public static Connection connect() throws SQLException, ClassNotFoundException {
		String driver="com.mysql.cj.jdbc.Driver",url="jdbc:mysql://localhost:3306/uamdatabase",username="root",password="root";
		Class.forName(driver);
		Connection c=DriverManager.getConnection(url,username,password);
		return c;

}

}
