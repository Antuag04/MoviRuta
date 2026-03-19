package com.security.mssecurity.Repositories;

import com.security.mssecurity.Models.Session;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface SessionRepository extends MongoRepository<Session, String> {
}
