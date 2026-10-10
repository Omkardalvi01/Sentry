# FUR-API DATASET

### Dataset statistics 
|          | Normal Samples | Anomaly Samples | Anomaly Type |
| -------- | -------------- | --------------- | ------------ |
| Training set | 20000 | 60 | 4 |
| Test set | 1000 | 150 | 7 |

## List of columns for the dataset
timestamp,	agent,	method,	request_body,	request_headers,	request_url,	response_body,	response_headers,	response_size,	source_ip,	source_port,	status,	target_ip,	target_port,	response_time,	user_identity, type.

## Basic features of each API request sample
```
timestamp: Time when the API request was made.  
agent: The client or software that initiated the API request.   
method: The type of HTTP request.  
request_body: Data sent by the client to the server in the API request.  
request_headers: Additional information sent by the client to the server along with the API request.  
request_url: Uniform Resource Locator that specifies the endpoint of the API being accessed.  
response_body: Data returned by the server in response to the API request.  
response_headers: Additional information sent by the server along with the API response.  
response_size: Size of the response sent by the server.  
source_ip: The IP address of the device or entity that initiated the API request.  
source_port: The port number on the source device that is used for the communication.   
status: The status code returned by the server indicates the outcome of the API request.  
target_ip: The IP address of the server or endpoint that received the API request.  
target_port: The port number on the target server where the API request is received and processed.  
response_time: Time taken by the server to process the API request and send back the response to the client.
user_identity: User identity for who initiated the request.
type: API request type.
```


## Anomaly Types
```
1. Injection Attack:
   Injection attacks involve maliciously injecting untrusted data into an application's input, which can then manipulate the application's behavior.

2. Directory Traversal Attack:
   A directory traversal attack, also known as a path traversal attack, occurs when an attacker tries to access files or directories outside of the intended scope by manipulating input parameters that represent file paths.

3. Cross-Site Scripting (XSS) Attack:
   Cross-site scripting attacks involve injecting malicious scripts into a web application that is then executed in the context of other users' browsers.

4. Performance Issue:
   This could include slow response times, high latency, or excessive resource utilization. Such anomalies can disrupt the user experience and affect the availability of the API.

5. Invalid Item Value:
   An API request with an invalid item value refers to providing data that does not adhere to the expected format or constraints.

6. Sensitive Data Leak:
   A sensitive data leak occurs when sensitive or confidential information is inadvertently exposed through an API response. This can happen due to improper data handling, misconfigured security settings, or other vulnerabilities, potentially leading to a breach of sensitive information.

7. Unauthorized Access Attack:
   An unauthorized access attack involves attempting to access resources or perform actions that the user is not authorized to do. This could involve exploiting vulnerabilities to gain access to restricted areas of an application or performing actions that should be restricted to certain users.
```

For the seven anomaly types mentioned above, the training set contains only four, and the test set contains four from the training set as well as an additional three unknown anomaly-type samples.
