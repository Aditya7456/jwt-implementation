package com.jwt.example.services;

import com.jwt.example.models.User;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Service
public class UserService {
    private final List<User> store = new ArrayList<>();

    public UserService(){
        store.add(new User(UUID.randomUUID().toString(),"Aditya","aditya@gmail.com"));
        store.add(new User(UUID.randomUUID().toString(),"Rahul","rahul@gmail.com"));
        store.add(new User(UUID.randomUUID().toString(),"Rohit","rohit@gmail.com"));
        store.add(new User(UUID.randomUUID().toString(),"Krishna","krishna@gmail.com"));
    }

    public List<User> getUsers(){
        return this.store;
    }


}
