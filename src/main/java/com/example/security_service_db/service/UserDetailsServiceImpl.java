package com.example.security_service_db.service;


import com.example.security_service_db.entities.Role;

import com.example.security_service_db.repository.UserRepository;

import org.springframework.security.core.GrantedAuthority;

import org.springframework.security.core.authority.SimpleGrantedAuthority;

import org.springframework.security.core.userdetails.*;

import org.springframework.stereotype.Service;

import java.util.ArrayList;

import java.util.Collection;

@Service

public class UserDetailsServiceImpl implements UserDetailsService {

    private final UserRepository userRepository;

    public UserDetailsServiceImpl(UserRepository userRepository) {

        this.userRepository = userRepository;

    }

    @Override

    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        var user = userRepository.findByUsername(username)

                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        Collection<GrantedAuthority> authorities = new ArrayList<>();

        user.getRoles().forEach(role -> {

            SimpleGrantedAuthority authority = new SimpleGrantedAuthority(role.getRoleName());

            authorities.add(authority);

        });

        org.springframework.security.core.userdetails.User userDetails = new org.springframework.security.core.userdetails.User(

                user.getUsername(),

                user.getPassword(),

                user.isEnabled(),

                true,

                true,

                true,

                authorities);

        return userDetails;

    }

}

