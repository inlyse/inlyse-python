# How to contribute to the python binding for the INLYSE API?

## Did you find a bug?
* **Do not open up a GitHub issue if the bug is a security vulnerability**, and instead to refer to our [security policy](https://github.com/inlyse/inlyse-python/blob/master/SECURITY.md).
* **Ensure the bug was not already reported** by searching on GitHub under [Issues](https://github.com/inlyse/inlyse-python/issues).
* If you're unable to find an open issue addressing the problem, [open a new one](https://github.com/inlyse/inlyse-python/issues/new).
  Be sure to include a **title and clear description**, as much relevant information as possible, and a **code sample** or an
  **executable test case** demonstrating the expected behavior that is not occurring.
* If possible, use the relevant bug report templates to create the issue.

## Did you write a patch that fixes a bug?
* Open a new GitHub pull request with the patch.
* Ensure the PR description clearly describes the problem and solution. Include the relevant issue number if applicable.
* The project uses semantic-release in order to cut a new release based on the commit-message. Please consider the
  [Angular Commit Message Conventions](https://github.com/angular/angular/blob/main/CONTRIBUTING.md#-commit-message-format).

## Do you intend to add a new feature or change an existing one?
* GitHub issues are primarily intended for bug reports and fixes. Please get in touch with us:
<info@inlyse.com>.

## Using git
For a well-done graphical introduction to Git, check this out:

http://pcottle.github.io/learnGitBranching/


### How to introduce a new feature or fix

#### Update the master branch
```Shell
$ git checkout master
$ git pull origin master
```

#### Create a new fix/feature branch
```Shell
$ git checkout -b <fix|feature>/<short description>
```

#### Do your work
```Shell
$ git add something
$ git commit -m "first commit"
$ git add another
$ git commit -m "second commit"
```

#### Push your local changes to origin
```Shell
$ git push origin <feature branch>
```

#### Open a Pull Request.
Open a Pull Request on Github and describe the changes.

## Do you have questions about the source code?
* Ask any question about how to use the python bindings for the INLYSE API in our [discussions](https://github.com/inlyse/inlyse-python/discussions) forum.


Thanks! :heart: :heart: :heart:

Your INLYSE team
