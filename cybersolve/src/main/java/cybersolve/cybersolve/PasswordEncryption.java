package cybersolve.cybersolve;

public class PasswordEncryption {
	private static final char[][] grid = {
	        {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I'},
	        {'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R'},
	        {'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a'},
	        {'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j'},
	        {'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's'},
	        {'t', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1'},
	        {'2', '3', '4', '5', '6', '7', '8', '9', '`'},
	        {'~', '!', '@', '#', '$', '%', '^', '&', '*'},
	        {'(', ')', '-', '_', '=', '+', '[', '{', ']'},
	        {'}', '|', ';', ':', '\'', ',', '<', '.', '>'},
	        {'/', '?'}
	    };
	public static String simpleHash(String password) {
        StringBuilder encryptedPassword = new StringBuilder();
        for (char c : password.toCharArray()) {
            int[] pos = findPosition(c);
            if (pos != null) {
                encryptedPassword.append(pos[0]).append(pos[1]);
            } else {
                encryptedPassword.append(c);
            }
        }
        return encryptedPassword.toString();
    }
	private static int[] findPosition(char c) {
        for (int i = 0; i < grid.length; i++) {
            for (int j = 0; j < grid[i].length; j++) {
                if (grid[i][j] == c) {
                    return new int[]{i+1, j+1};
                }
            }
        }
        return null;
    }

}
