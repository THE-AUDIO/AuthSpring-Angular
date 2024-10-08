package nandraina.AuthSpring_Angular.controller;

import nandraina.AuthSpring_Angular.model.UserEntity;
import nandraina.AuthSpring_Angular.service.AuthService;
import nandraina.AuthSpring_Angular.service.JWTService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
public class AuthController {
    @Autowired
    private JWTService jwtService;

    @Autowired
    private AuthService authService;
    @PostMapping("/login")
    public String getToken(Authentication authentication){
        // Perform authentication and return JWT token
        return jwtService.generateToken(authentication);
    }
    @GetMapping("/resources")
    public  String getResources(){
        return "my resource";
    }
    @PostMapping("/registry")
    public  UserEntity registry(@RequestBody UserEntity user){
      return this.authService.saveUser(user);
    }
}
