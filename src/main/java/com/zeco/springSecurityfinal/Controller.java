package com.zeco.springSecurityfinal;


import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.web.bind.annotation.*;

@RestController
public class Controller {

    private final AuthenticationManager authenticationManager;
    private final SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder.getContextHolderStrategy();
    private final SecurityContextRepository securityContextRepository = new HttpSessionSecurityContextRepository();



    public Controller(AuthenticationManager authenticationManager ) {
        this.authenticationManager = authenticationManager;

    }


    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestBody LoginRequest loginRequest, HttpServletRequest request, HttpServletResponse response) {



        Authentication authenticationRequest = UsernamePasswordAuthenticationToken.unauthenticated(loginRequest.getUsername(), loginRequest.getPassword());

        Authentication authenticationResponse = this.authenticationManager.authenticate(authenticationRequest);

        SecurityContext context = this.securityContextHolderStrategy.createEmptyContext();
        context.setAuthentication(authenticationResponse);
        this.securityContextHolderStrategy.setContext(context);
        securityContextRepository.saveContext(context, request, response);
        //SecurityContextHolder.getContext().setAuthentication(authenticationResponse);



        /***
        with this one method from Gemini, you will need to add this to http filter chain : .securityContext((securityContext) -> securityContext
            .securityContextRepository(new HttpSessionSecurityContextRepository())
        ); for it to work

        SecurityContextHolder.getContext().setAuthentication(authenticationResponse);
        HttpSession session = request.getSession(true); // Ensure session is created
        session.setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY, SecurityContextHolder.getContext());*/




        if(authenticationResponse.isAuthenticated()){
            System.out.println("motherfucker just got authenticated");
        }


        return ResponseEntity.ok("great job");
    }

    @PostMapping("/test1")
    public String test1(@RequestBody LoginRequest loginRequest){

        System.out.println("***************************************************************");
        System.out.println(loginRequest);
        return "test1";
    }


    @GetMapping("/test2")
    //@PreAuthorize("hasRole('ROLE_USER')")
    public String test2(){
        return "test2";
    }


    @GetMapping("/test3")
    public String test3(){
        return "test3";
    }


}
