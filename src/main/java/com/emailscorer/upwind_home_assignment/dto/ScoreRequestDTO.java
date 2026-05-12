package com.emailscorer.upwind_home_assignment.dto;
import java.util.List;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
public class ScoreRequestDTO {

     @Size(max = 50000, message = "Email content is too large to process safely")
     private String emailContent;
     @Size(max = 255, message = "Sender header is too large")
     private String sender;

     @Size(max = 255, message = "Reply-To header is too large")
     private String replyTo;
     @Size(max = 100, message = "Too many attachments")
     private List<String> attachmentNames;

     private boolean dmarcFailed;

     public String getEmailContent() {
          return emailContent; }

     public void setEmailContent(String emailContent) {
          this.emailContent = emailContent; }

     public String getSender() {
          return sender; }

     public void setSender(String sender) { 
          this.sender = sender; }

     public String getReplyTo() { 
          return replyTo; }
          
     public void setReplyTo(String replyTo) {
          this.replyTo = replyTo; }

     public List<String> getAttachmentNames() { 
          return attachmentNames; }

     public void setAttachmentNames(List<String> attachmentNames) { 
          this.attachmentNames = attachmentNames; }
     public boolean isDmarcFailed() {
          return dmarcFailed;}

     public void setDmarcFailed(boolean dmarcFailed) {
          this.dmarcFailed = dmarcFailed;}
}

