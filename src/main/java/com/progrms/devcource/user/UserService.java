package com.progrms.devcource.user;

import lombok.RequiredArgsConstructor;
//import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional
//implements UserDetailsService
public class UserService {

    private final PasswordEncoder passwordEncoder;

    private final UserRepository userRepository;

    public UserService(PasswordEncoder passwordEncoder, UserRepository userRepository) {
        this.passwordEncoder = passwordEncoder;
        this.userRepository = userRepository;
    }

    //    @Override
//    @Transactional(readOnly = true)
//    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
//        return userRepository.findByLoginId(username)
//                .map(u ->
//                        User.builder()
//                                .username(u.getLoginId())
//                                .password(u.getPasswd())
//                                .authorities(u.getGroup().getAuthorities())
//                                .build()
//                )
//                .orElseThrow(() -> new UsernameNotFoundException("Could not found user for " + username));
//    }

    @Transactional(readOnly = true)
    public User login(String username, String credentials) {
        User user = userRepository.findByLoginId(username)
                .orElseThrow(() -> new UsernameNotFoundException("Could not found user for " + username));
        user.checkPassword(passwordEncoder, credentials);
        return user;
    }

}
