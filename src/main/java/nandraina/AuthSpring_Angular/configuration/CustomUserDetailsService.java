package nandraina.AuthSpring_Angular.configuration;

import nandraina.AuthSpring_Angular.model.UserEntity;
import nandraina.AuthSpring_Angular.repository.AuthRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
@Service
public class CustomUserDetailsService implements UserDetailsService {
    @Autowired
    private AuthRepository authRepository;
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserEntity user = this.authRepository.findByUsername(username);
        System.out.println("dans customUserDetails "+user);
        if(user == null){
           throw new UsernameNotFoundException("username " + username + " not found");
        }
        return new User(user.getUsername(), user.getPassword(),getGrantedAuthority(user.getRole()));
    }
    private List<GrantedAuthority> getGrantedAuthority(String role){
        List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
        authorities.add(new SimpleGrantedAuthority("ROLE_"+role));
        return authorities;
    }
}
