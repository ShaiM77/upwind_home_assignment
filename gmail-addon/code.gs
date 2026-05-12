var BACKEND_URL = "https://scarcity-nurture-slum.ngrok-free.dev/api/score";
var API_KEY = "assignment-secret-key"; // used to secure the connection, making sure that Java backend only processes requests coming from this specific add-on

function buildAddOn(e) {
  var accessToken = e.gmail.accessToken;
  var messageId = e.gmail.messageId;
  GmailApp.setCurrentMessageAccessToken(accessToken);
  
  // Get the email content and headers
  var message = GmailApp.getMessageById(messageId);
  var body = message.getPlainBody();
  var sender = message.getFrom();
  var replyTo = message.getReplyTo();
  var attachments = message.getAttachments()
  var attachmentNames = [];
  for (var i = 0; i < attachments.length; i++) { //we only want to send the name of the files not the actual files
    attachmentNames.push(attachments[i].getName());
  }
  // Extract Google's pre-calculated authentication results
  var authHeader = message.getHeader("Authentication-Results") || "";
  var dmarcFailed = authHeader.toLowerCase().indexOf("dmarc=fail") > -1;

  // Prepare the secure payload
  var options = {
    'method' : 'post',
    'contentType': 'application/json',
    'headers': {
      'X-API-KEY': API_KEY
    },
    'payload' : JSON.stringify({
      'emailContent': body,
      'sender': sender,
      'replyTo': replyTo,
      'attachmentNames': attachmentNames,
      'dmarcFailed': dmarcFailed
    })
  };

  try {
    // Send to Java backend
    var response = UrlFetchApp.fetch(BACKEND_URL, options);
    
    // Check if the Java app rejected us meaning the api key was not correct or we have validation failure, or server crash
    if (response.getResponseCode() !== 200) {
       return createErrorCard("Server rejected the request. Status: " + response.getResponseCode());
    }

    var result = JSON.parse(response.getContentText());
    return createResultCard(result);
    
  } catch (err) {
    return createErrorCard(err.toString());
  }
}

function createResultCard(data) {
  var icon = data.verdict === "Malicious" ? "❌" : "✅";
  
  var header = CardService.newCardHeader()
      .setTitle("Suspicious Email Scorer")
      .setSubtitle("Result: " + data.verdict);

  var section = CardService.newCardSection()
      .addWidget(CardService.newTextParagraph().setText("<b>Score: " + data.score + "/100</b> " + icon));

  if (data.reasons && data.reasons.length > 0) {
    var reasonsText = "<b>Reasons:</b><br/>" + data.reasons.join("<br/>");
    section.addWidget(CardService.newTextParagraph().setText(reasonsText));
  } else {
    section.addWidget(CardService.newTextParagraph().setText("No suspicious indicators found."));
  }

  return CardService.newCardBuilder()
      .setHeader(header)
      .addSection(section)
      .build();
}

function createErrorCard(error) {
  return CardService.newCardBuilder()
      .setHeader(CardService.newCardHeader().setTitle("Connection Error"))
      .addSection(CardService.newCardSection()
          .addWidget(CardService.newTextParagraph().setText("Error: " + error)))
      .build();
}