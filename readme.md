## Closed Links
# Improving username validations
 In the current implementation the username is made optional by default and we updated so that the username should be required making the data consistent and integrity while simplyfying both validations and downstream operations that depend on the existence of a nickname.
URL : https://github.com/mv492/Assignment-10/issues/1

# Special character validations
 In this initial implementation of username validation was too permissive. It allowed unsupported characters. This could lead to use data inconsistencies and potential security issues. With the updated code the any username that doesn't comply with validation rules throws an error.
URL : https://github.com/mv492/Assignment-10/issues/3

# Min/Max username Validation
 This validation makes sure the username taken follows the minimum length and maximum length by the user.

 URL : https://github.com/mv492/Assignment-10/issues/5

 # Password Min/Max Validation
 The password validation logic was modified to include checks for a minimum length of 8 characters and maximum length of 20 characters.

 URL : https://github.com/mv492/Assignment-10/issues/7

 # Unique Email verification
 Without enforcing uniqueness on critical fields like email and nickname, it’s possible for duplicate user records to exist. This can lead to issues during authentication, conflicts in user identity, and overall inconsistency in user management.

 URL : https://github.com/mv492/Assignment-10/issues/10


 ## My understanding with this assignment

 Working on this assignment has significantly deepened my understanding of REST API development and quality assurance in a collaborative environment. I enhanced my skills in debugging and writing comprehensive test cases for various aspects of the API, including user input validation and password security. Implementing proper password hashing and enforcing uniqueness constraints presented specific challenges that forced me to consider both security and consistency across the application.

  The assignment provided numerous opportunities to collaborate using Git and GitHub. I learned to efficiently manage issues, create well-documented pull requests, and leverage code reviews to improve the overall code quality. The iterative process of addressing real-world issues – from updating schema validations to refining integration tests – has not only strengthened my technical expertise but also highlighted the importance of clear communication and thorough documentation in a software development team.

