package nandraina.AuthSpring_Angular.service;

import nandraina.AuthSpring_Angular.model.UserEntity;
import nandraina.AuthSpring_Angular.repository.AuthRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class AuthService {
    @Autowired
    private AuthRepository authRepository;
    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    public UserEntity saveUser(UserEntity user){
        user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
        return authRepository.save(user);
    }
}
