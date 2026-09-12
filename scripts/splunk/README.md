# Splunk Scripts

## Dependencies

To install dependencies using pip you can run the following command:

```
pip install -r requirements.txt
```

## IC feed to Splunk key-value store

The script `ic_feed_to_splunk_kvstore.py` add the indicators from an Intelligence Center feed to a Splunk key value store.

### Configuration:

The following configuration must be provided in the script:
* `API_KEY`: The intelligence center API Key
* `SPLUNK_COLLECTION_NAME`: Name of the kvstore collection in Splunk
* `SPLUNK_CONNECTION`: Credentials to connect to the splunk instance

Some other parameters may be provided but are not required:
* `FEED_ID`: ID of the feed to consumme. By default it uses the default feed.
* `CURSOR_FILE`: File where the cursors will be stored. The cursor allow the script to not restart from the beggining when running again.
* `REQUEST_EXTRA`: Additional parameters to provide to the `requests` module. It is usefull to provide proxy informations for example.
