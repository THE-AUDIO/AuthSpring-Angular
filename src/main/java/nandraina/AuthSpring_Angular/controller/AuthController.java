package nandraina.AuthSpring_Angular.controller;

import nandraina.AuthSpring_Angular.model.UserEntity;
import nandraina.AuthSpring_Angular.service.AuthService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AuthController {
    @Autowired
    private AuthService authService;
    @GetMapping("/")
    public  String Home(){
        return "salut";
    }
    @PostMapping("/registry")
    public UserEntity registry(@RequestBody UserEntity user){
        System.out.println(user);
        return this.authService.saveUser(user);
    }
}
