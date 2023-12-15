package com.example.demo;

import org.apache.catalina.User;
import org.apache.juli.logging.Log;
import org.springframework.stereotype.Service;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.util.*;

@Service
public class UserStore {
    private static final Logger logger = LoggerFactory.getLogger(UserStore.class);
    private Map<String, String> userCredentials = Collections.synchronizedMap(new HashMap<>());
    private Set<String> validUsers = Collections.synchronizedSet(new HashSet<>() {{
        add("sehpkk");
        add("scr28f");
    }});
    private static final String FILE_PATH = "C:\\Users\\sehpkk\\Desktop\\userstore.dat";

    public UserStore() {
        loadCredentials();
        logger.info(userCredentials.toString());
    }

    public synchronized boolean addUser(String username, String password) {
        logger.info("adding user: {}", username);
        if (validUsers.contains(username)) {
            logger.info("User Registering");
            String hashedPassword = BCrypt.hashpw(password, BCrypt.gensalt());
            userCredentials.put(username, hashedPassword);
            saveCredentials();
            return true;
        }
        return false;
    }

    public boolean checkPassword(String username, String password) {
        String storedHash = userCredentials.get(username);
        return storedHash != null && BCrypt.checkpw(password, storedHash);
    }

    public synchronized void changePassword(String username, String password) {
        if (userCredentials.containsKey(username)) {
            String hashedNewPass = BCrypt.hashpw(password, BCrypt.gensalt());
            userCredentials.put(username, hashedNewPass);
            saveCredentials();
        }
    }

    private void saveCredentials() {
        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(FILE_PATH))) {
            oos.writeObject(userCredentials);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @SuppressWarnings("unchecked")
    private void loadCredentials() {
        File file = new File(FILE_PATH);
        if (file.exists()) {
            try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(file))){
                Object readMap = ois.readObject();
                if (readMap instanceof Map) {
                    userCredentials = Collections.synchronizedMap((Map<String, String>) readMap);
                }
            } catch (IOException | ClassNotFoundException e) {
                e.printStackTrace();
            }
        }
    }

    public String getPasswordForUser(String username) {
        if (userCredentials.containsKey(username)) {
            return userCredentials.get(username);
        }
        return null;
    }
}
