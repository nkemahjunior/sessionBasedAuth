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
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;

@RestController
public class Controller {

    private final AuthenticationManager authenticationManager;
    private final SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder.getContextHolderStrategy();
    private final SecurityContextRepository securityContextRepository = new HttpSessionSecurityContextRepository();


    private final String HOME_VIEW_COUNT = "HOME_VIEW_COUNT";

    SecurityContextLogoutHandler logoutHandler = new SecurityContextLogoutHandler();



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

    @PostMapping("/logout1")
    public Test3 performLogout(Authentication authentication, HttpServletRequest request, HttpServletResponse response) {
        // .. perform logout
        this.logoutHandler.logout(request, response, authentication);

        Test3 obj = new Test3();
        obj.setTest3Data("sucessfully logout");

        return obj;
    }

    @PostMapping("/test1")
    public String test1(@RequestBody LoginRequest loginRequest){

        System.out.println("***************************************************************");
        System.out.println(loginRequest);
        return "test1";
    }


    @PostMapping("/test2")
    //@PreAuthorize("hasRole('ROLE_USER')")
    public Test3 test2(@RequestBody Test3 test3){
        System.out.println("################################################################################################################");
        System.out.println("################################################################################################################");
        System.out.println(test3);
        System.out.println("################################################################################################################");
        System.out.println("################################################################################################################");

        return test3;
    }


    @GetMapping("/test3")
    public Test3 test3(){

        Test3 obj = new Test3();
        obj.setTest3Data("yessssssssssssssssss you did it");
        return obj;
    }

    @GetMapping("/track")
    public String track(Principal principal, HttpSession session){
        incrementCount(session,HOME_VIEW_COUNT);
        return "hello, " + principal.getName();
    }

    @GetMapping("/count")
    public String count(HttpSession session){
        return  "HOME_VIEW_COUNT : " + session.getAttribute(HOME_VIEW_COUNT);
    }


    public void incrementCount(HttpSession session,String attr){
        int homeViewCount =  session.getAttribute(attr) == null ? 0 : (Integer)session.getAttribute(attr);
        session.setAttribute(attr,homeViewCount);
    }


}
