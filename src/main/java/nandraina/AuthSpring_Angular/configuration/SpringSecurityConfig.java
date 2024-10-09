package nandraina.AuthSpring_Angular.configuration;

import com.nimbusds.jose.jwk.source.ImmutableSecret;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;


import javax.crypto.spec.SecretKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;

@Configuration
@EnableWebSecurity
public class SpringSecurityConfig {
        private String jwtKey ="MEgCQQC/Yc2qCMG6anjpyi5ORqXy0he9ECsXYwt7kF/AnXio1eh3PjkFMEvXBPMe";
        @Autowired
        private CustomUserDetailsService customUserDetailsService;
        @Bean
        public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
            return http
                    .csrf(AbstractHttpConfigurer::disable)
                    .sessionManagement(session->{
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS);
                    })
                    .authorizeHttpRequests((auth)->{
                        auth.requestMatchers("/admin").hasRole("ADMIN");
                        auth.requestMatchers("/user").hasRole("USER");
                        auth.requestMatchers("/registry").permitAll();
                        auth.anyRequest().authenticated();
                    })
                    .oauth2ResourceServer(oauth -> oauth.jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter())))

//                    .oauth2ResourceServer(oauth -> oauth.jwt(Customizer.withDefaults()))
                    .httpBasic(Customizer.withDefaults())
                    .build();
        }
    
        @Bean
        public BCryptPasswordEncoder passwordEncoder(){
            return new BCryptPasswordEncoder();
        }
    
        @Bean
        public JwtEncoder jwtEncoder(){
            return new NimbusJwtEncoder(new ImmutableSecret<>(this.jwtKey.getBytes()));
        }
    
        @Bean
        public JwtDecoder jwtDecoder(){
            SecretKeySpec secretKey = new SecretKeySpec(this.jwtKey.getBytes(), 0, this.jwtKey.getBytes().length,"HmacSHA256");
            return NimbusJwtDecoder.withSecretKey(secretKey).macAlgorithm(MacAlgorithm.HS256).build();
        }
    
        @Bean
        public AuthenticationManager authenticationManager(HttpSecurity http, BCryptPasswordEncoder bCryptPasswordEncoder) throws Exception{
            AuthenticationManagerBuilder authenticationManagerBuilder = http.getSharedObject(AuthenticationManagerBuilder.class);
            authenticationManagerBuilder.userDetailsService(customUserDetailsService).passwordEncoder(bCryptPasswordEncoder);
            return  authenticationManagerBuilder.build();
        }

    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();

        // Définir un convertisseur de claim personnalisé pour extraire les rôles
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(jwt -> {
            Collection<GrantedAuthority> authorities = new ArrayList<>();

            // Extraire les rôles du claim `roles` ou autre champ selon votre token
            String roles = jwt.getClaimAsString("roles");
            if (roles != null) {
                // Convertir les rôles en SimpleGrantedAuthority (nécessaire pour Spring Security)
                Arrays.stream(roles.split(",")).forEach(role ->
                        authorities.add(new SimpleGrantedAuthority(role))
                );
            }
            System.out.println(authorities);
            return authorities;
        });

        return jwtAuthenticationConverter;
    }

}