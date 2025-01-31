pub struct NetworkContainer {}

// TODO: The container is populated as the user is navigating a binary
// TODO: We need to have a few helper functions here to post and pull
// TODO: Then in the interface we operate off the network cache
// TODO: The network cache could just be a disk container? Or disk container sources?
// TODO: We should also store the cache on the filesystem for a certain time, will need to timestamp
// TODO: When we commit we need to actually POST i believe.
// TODO: There needs to be a setting that adjusts the sweep size of functions at the cursor.
// TODO: Probably need a callback or something to tell the network containers to refresh from the network.
// TODO: The network container should never instantiate itself, unless its gurenteed to not have any data in it?

// TODO: Need to PUSH chunks and PULL chunks
