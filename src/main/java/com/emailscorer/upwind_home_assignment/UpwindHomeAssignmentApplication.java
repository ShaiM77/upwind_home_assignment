package com.emailscorer.upwind_home_assignment;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class UpwindHomeAssignmentApplication {

	private static final Logger logger = LoggerFactory.getLogger(UpwindHomeAssignmentApplication.class);

	public static void main(String[] args) {
		logger.info("Starting Upwind Home Assignment Email Scoring Application");
		SpringApplication.run(UpwindHomeAssignmentApplication.class, args);
		logger.info("Upwind Home Assignment Email Scoring Application started successfully");
	}

}
