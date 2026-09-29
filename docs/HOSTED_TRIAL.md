# Hosted Warden trial

The hosted trial at `warden.uranledgr.com` is a separate service operated by the Warden project. It is not required to run Warden Community.

## Trial limits

- The trial lasts exactly 14 days and does not renew automatically.
- No payment card is required.
- One person may create one trial.
- A trial supports up to 10 endpoints, three administrators, and three branches.

## Expiry and deletion

The console shows the expiry time throughout the trial. Unless the organization is converted before that time, Warden revokes the endpoint records and permanently deletes the trial organization and its tenant data. An installed agent can no longer authenticate after its endpoint record is deleted.

Export anything needed before the displayed expiry time. Deletion is not a backup or archive workflow and cannot be undone through the trial console.

## Contact record

The signup form separately asks for permission to retain the contact name, work email, organization name, signup source, trial dates, and follow-up status. Warden keeps this small lead record after the trial workspace is deleted so the operator can contact people who evaluated the hosted service and prevent repeated trials. The contact fields are encrypted at rest. Endpoint inventory, policies, jobs, files, secrets, and other tenant data are not copied into the lead record.

Do not start a hosted trial unless you accept both the deletion policy and this contact use. Use the contact address shown by the hosted service to request correction or deletion of the retained lead record.

## Converting before expiry

Contact the hosted Warden operator from the in-console trial banner. Conversion changes the subscription out of trial state before expiry; converted organizations are excluded from automatic trial deletion.
