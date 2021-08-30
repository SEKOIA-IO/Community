# Events

This section contains data files that are used by the Operation Center to help analysts better understand their events.

## smart-descriptions.json

This file is used to provide analysts with an understandable version of their events. Here is an example, as seen on the Events page:

![image](https://user-images.githubusercontent.com/35897/111750859-0e37b000-8894-11eb-9f47-1947000f4086.png)

And here is the part of the JSON file responsible for this description:

```json
{
  "windows": [
    {
      "value": "{user.domain}\\{user.name} logged on to {log.hostname} with special privileges",
      "relationships": [{
        "source": "user.name",
        "target": "log.hostname",
        "type": "logged on to"
      }],
      "conditions": [{
          "field": "action.id",
          "value": 4672
        },
        {
          "field": "event.provider",
          "value": "Microsoft-Windows-Security-Auditing"
        }
      ]
    },
  ]
}
```

The JSON file contains a list of descriptions associated with an intake name (here: "windows"). Each description has the following properties:

* `value`: the Smart Description itself, with variables from the event expressed as `{ECS_EVENT_PATH}`
* `conditions`: a set of conditions that should be met for this description to be used. Each condition has a `field` name and a `value`. A condition without a `value` means that the field should be set (whatever the value).
* `relationships` (optional): this will be used in the future to display events inside an investigation graph. Each relationship should have a `source` (object path), a `target` (object path) and a `type` (text, description of the relationship, with variables from the event expressed as `{ECS_EVENT_PATH}`).

When several conditions match the same event, the Smart Description with the most conditions is used.

## lookups.json

This file is used to provide a friendly description for some event constants that are usually meant for machines. Here is an example as seen on the Events page:

![image](https://user-images.githubusercontent.com/35897/111752811-6f608300-8896-11eb-843f-b479178b8503.png)

And here is the corresponding part of the JSON file:

```json
{
  "action.properties.LogonType": [{
    "values": {
      "0": "System - Used only by the System account, for example at system startup.",
      "2": "Interactive - A user logged on to this computer.",
      "3": "Network - A user or computer logged on to this computer from the network.",
      "4": "Batch - Batch logon type is used by batch servers, where processes may be executing on behalf of a user without their direct intervention.",
      "5": "Service - A service was started by the Service Control Manager.",
      "7": "Unlock - This workstation was unlocked.",
      "8": "NetworkCleartext - A user logged on to this computer from the network. The user's password was passed to the authentication package in its unhashed form.",
      "9": "NewCredentials - A caller cloned its current token and specified new credentials for outbound connections. The new logon session has the same local identity, but uses different credentials for other network connections.",
      "10": "RemoteInteractive - A user logged on to this computer remotely using Terminal Services or Remote Desktop.",
      "11": "CachedInteractive - A user logged on to this computer with network credentials that were stored locally on the computer. The domain controller was not contacted to verify the credentials.",
      "12": "CachedRemoteInteractive - Same as RemoteInteractive. This is used for internal auditing.",
      "13": "CachedUnlock - Workstation logon."
    },
    "conditions": []
  }],
}
```

The JSON file contains a lookup table associated with each object path (`action.properties.LogonType` in this example). Each lookup table has the following properties:

* `values`: an object with the actual values as keys and the associated descriptions as values
* `conditions`: a set of conditions, similar to the ones used for the Smart Descriptions. When the list is empty, it means that the lookup table always applies for this field.

## Testing Changes

When making changes to these files, you can test your changes directly from your browser by using special cookies values:

* `event-smart-descriptions`: set this cookie to an URL hosting your modified `smart-descriptions.json` file
* `event-lookups`: set this cookie to an URL hosting your modified `lookups.json` file

Do not forget to remove these cookies once you are done, or make sure to limit their lifetime to the session.

### Testing changes locally

In order to test changes from local copies of the file, you can use a simple webserver such as `http-server --cors -p 8000`. `http-server` can be installed with `npm install http-server`.

When using this local server, you should then set (depending on which file you are modifying):

* `event-smart-descriptions` to `http://localhost:8000/smart-descriptions.json`
* `event-lookups` to `http://localhost:8000/lookups.json`

### Testing changes from a GitHub fork

You can also test your changes by creating a GitHub fork and use the raw URL inside the cookies:

* `event-smart-descriptions` to `https://raw.githubusercontent.com/SEKOIA-IO/Community/main/events/smart-descriptions.json`
* `event-lookups` to `https://raw.githubusercontent.com/SEKOIA-IO/Community/main/events/lookups.json`

Replace `SEKOIA-IO/Community` with the path to your GitHub fork.

