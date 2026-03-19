package com.security.mssecurity.Services;

import com.security.mssecurity.Models.Session;
import com.security.mssecurity.Repositories.SessionRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class SessionService {

    @Autowired
    private SessionRepository sessionRepository;

    public List<Session> find(){
        return this.sessionRepository.findAll();
    }

    public Session findById(String id){
        return this.sessionRepository.findById(id).orElse(null);
    }

    public Session create(Session newSession){
        return this.sessionRepository.save(newSession);
    }

    public Session update(String id, Session newSession){
        Session actualSession = this.sessionRepository.findById(id).orElse(null);

        if(actualSession != null){
            actualSession.setToken(newSession.getToken());
            actualSession.setExpiration(newSession.getExpiration());
            actualSession.setCode2FA(newSession.getCode2FA());
            this.sessionRepository.save(actualSession);
            return actualSession;
        } else {
            return null;
        }
    }

    public void delete(String id){
        Session theSession = this.sessionRepository.findById(id).orElse(null);
        if(theSession != null){
            this.sessionRepository.delete(theSession);
        }
    }
}
