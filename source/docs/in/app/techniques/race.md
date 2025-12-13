# Race conditions

A race condition happens when two sections of code that are designed to be executed in a sequence get executed out of sequence.

## Steps

1. Spot the features prone to race conditions in the target application and copy the corresponding requests.
2. Send multiple of these critical requests to the server simultaneously. You should craft requests that should be allowed once but not allowed multiple times.
3. Check the results to see if your attack has succeeded. And try to execute the attack multiple times to maximise the chance of success.
4. Consider the impact of the race condition you just found.
5. Draft up the report.

## Find features prone to race conditions

Attackers use race conditions to subvert access controls. In theory, any application whose sensitive actions rely on access-control mechanisms could be vulnerable. Most of the time, race conditions occur in features that deal with numbers, such as online voting, online gaming scores, bank transfers, e-commerce payments, and gift card balances. Look for these features in an application and take note of the request involved in updating these numbers.

## Send simultaneous requests

Then test for and exploit race conditions in the target by sending multiple requests to the server simultaneously.

## Check the results

Check if your attack has succeeded.

Whether the attack succeeds depends on the server's process-scheduling algorithm, which is a matter of luck. However, the more requests you send within a short time frame, the more likely the attack will succeed.

## Create a Proof of Concept

Once you have found a race condition, you will need to provide proof of the vulnerability in your report. The best way to do this is to lay out the steps needed to exploit the vulnerability.

## Escalation

Race condition vulnerabilities can have a significant impact on the functionality and security of an application. When determining the impact of a specific race condition, pay attention to how much an attacker can potentially gain in terms of monetary reward or social influence.

If a race condition is found on a critical functionality like cash withdrawal, fund transfer, or credit card payment, the vulnerability could lead to infinite financial gain for the attacker. Prove the impact of a race condition and articulate what attackers will be able to achieve.

## Portswigger lab writeups

* [Web shell upload via race condition](../burp/upload/7.md)

## Remediation

The simplest ways to eliminate race conditions are to remove the potential for parallel processing within an application or to ensure that different threads of execution do not share resources.

This may not be an option and it can negatively impact program performance. Two options for fixing the issue are the use of thread-safe programming and randomisation. 

## Resources

* [Portswigger Lab: Web shell upload via race condition](https://portswigger.net/web-security/file-upload/lab-file-upload-web-shell-upload-via-race-condition)
* [How to Prevent Race Conditions in Web Applications](https://www.kroll.com/en/insights/publications/cyber/race-condition-web-applications)


