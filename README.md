# Voided.to Authentication CSharp By C911

 A C# Code to help you integerate Voided.To Auth system to your own tools

## Getting Started
You will need to add referenc for :
# - Newtonsoft.Json
# - JWT
## Preferance
as you see in Program.cs there is this Line
```C#
List<string> requiredRankMinimum = new List<string> { "vip", "exclusive", "cosmo" };
```
This is the allowed Ranks that are allowed to use the software you're building (You can change that depending on your Desire or Admins Consult)
## Signs of Passing the auth system
```C#
bool authed = false;
```
At the end if a user is authed with no issues with Variable will be set to "True" as a Boolean
there is also a a log print to console for User is authed or any other conditions
## Authors

    Colorles911
