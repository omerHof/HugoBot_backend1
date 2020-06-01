# HugoBotServer
The system will be able to identify whether a user browsing the site is registered to the system.
1.1 We will use the token securely
2. The module responsible for registration will be part of user management.
2.1. When a user is successfully registered, they will see a message that they have successfully registered.
3. The module responsible for connecting will be part of user management.
3.2. The login will be done using a username and password.
4. A registered user will be able to upload their own Datasets to the site.
4.1. The system must not allow the user to upload a non-compliant Dataset as follows:
The csv header from left to right: entity code, temporal variable code, timestamp code, value
4.2. In addition to the data itself, the system will also require an entity code mapping file for their verbal description (Vmap file, variable map)
4.3 In addition to the data itself, the system will allow the user to upload the entity classification in 2 formats: in a separate file, or as an appendix at the end of the data file
4.3.1. In both formats the variable code will be -1, the timestamp code is 0, and the value is 0 or 1 depending on the actual classification.
4.4. A user who uploaded Dataset to the system reserves the right to delete it at any time.
5. When a Dataset is uploaded or at any point after uploading, a registered user can determine whether they want it to be public or private.
5.1. Difficultly, Dataset configured as private is blocked for viewing and access except for the user who uploaded it.
5.2. Complementarily, a publicly-configured Dataset is open for viewing by any site user.
5.3. The system will allow a registered user to give other users view access to Dataset, provided that user has uploaded the Dataset.
5.4 Permission to Dataset only allows it to be used and the system will not allow its deletion.
6. Only registered users will be able to use any Datasets, regardless of whether they are public or private.
7. A user with access to Dataset can discriminate (Temporal Abstraction) on him.
7.1. The system will allow the user to set the run parameters: the discretization method, the number of intersections, the PAA window size (dipole 1), and the maximum interval between points that can be grouped into a single time interval (max gap).
7.2. The system will save previous runs according to the above parameters, allowing the user who ran it and other users with access to download the results and / or use them later for mining.
7.2.1. The system will not allow the user to discretize that has been previously run.
7.3 The system will allow the user with access to download the discretization outputs to his personal computer by watching them.
              

8. A user with Dataset access will be able to choose discretization and run the KarmaLego algorithm on it.
8.1. The system will not allow the user to choose discretization whose run is not over yet.
8.2 The system will allow the user to set the run parameters.
8.3. The system will save previous runs according to the above parameters, allowing the user who ran it and other users with access to download the results and / or use them later for visualization.
8.3.1. The system will not allow the user to perform mining that has been previously run.
8.4. Similar to requirement 7.3, completed mining run outputs will be available for download.
9. A user with access to Dataset will be able to select templates and visualize them.
9.1 The system will not allow the user to visualize mining that has not completed its run.

and. Non-functional requirements:

1. The site load time must be reasonable, the html page should load within a few seconds.
2. A user-friendly indicator will be displayed when output is unavailable for use.
3. The system will allow the use of a number of known discretization algorithms, such as:
Persist, TD4C EWD, EDD, SAX, TD4C, K-means, Domain Expert, and more.
4. A user can easily manage the permissions for Datasets he uploaded. The system must provide a clear graphical interface that will allow the user to conveniently manage permissions.
5. User passwords will be saved with scrambling functions.
6. The system will be immune to sql injection.
