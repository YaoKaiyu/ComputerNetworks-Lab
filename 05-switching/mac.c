#include "mac.h"
#include "headers.h"
#include "log.h"

mac_port_map_t mac_port_map;

void init_mac_hash_table()
{
	bzero(&mac_port_map, sizeof(mac_port_map_t));

	pthread_mutexattr_init(&mac_port_map.attr);
	pthread_mutexattr_settype(&mac_port_map.attr, PTHREAD_MUTEX_RECURSIVE);
	pthread_mutex_init(&mac_port_map.lock, &mac_port_map.attr);

	pthread_create(&mac_port_map.tid, NULL, sweeping_mac_port_thread, NULL);
}

void destory_mac_hash_table()
{
	pthread_mutex_lock(&mac_port_map.lock);
	mac_port_entry_t *tmp, *entry;
	for (int i = 0; i < HASH_8BITS; i++) {
		entry = mac_port_map.hash_table[i];
		if (!entry) 
			continue;

		tmp = entry->next;
		while (tmp) {
			entry->next = tmp->next;
			free(tmp);
			tmp = entry->next;
		}
		free(entry);
	}
	pthread_mutex_unlock(&mac_port_map.lock);
}

iface_info_t *lookup_port(u8 mac[ETH_ALEN])
{
	// TODO: implement the lookup process here
	// fprintf(stdout, "TODO: implement the lookup process here.\n");
	pthread_mutex_lock(&mac_port_map.lock);
	u8 hash_value = hash8((unsigned char *)mac, sizeof(u8)*ETH_ALEN);
	mac_port_entry_t * entry = mac_port_map.hash_table[hash_value];
	while(entry){
		if(!memcmp(entry->mac, mac, sizeof(u8)*ETH_ALEN)){
			// fprintf(stdout, "Port comparing succeeded.\n");
			pthread_mutex_unlock(&mac_port_map.lock);
            return entry->iface;
		}
		entry = entry->next;
	}
	// fprintf(stdout, "Port comparing failed.\n");
	pthread_mutex_unlock(&mac_port_map.lock);
	return NULL;
}

void insert_mac_port(u8 mac[ETH_ALEN], iface_info_t *iface)
{
	// TODO: implement the insertion process here
	// fprintf(stdout, "TODO: implement the insertion process here.\n");
	pthread_mutex_lock(&mac_port_map.lock);

    // create a new mac_port_entry && initialize its info
	mac_port_entry_t * new_entry = (mac_port_entry_t *)malloc(sizeof(mac_port_entry_t));
	bzero(new_entry, sizeof(mac_port_entry_t));
	new_entry->next = NULL;
	new_entry->iface = iface;
	new_entry->visited = time(NULL);
	memcpy(new_entry->mac, mac, sizeof(u8)*ETH_ALEN);
	// caculate the hash value of MAC && insert it into hash table
	u8 hash_value = hash8((unsigned char *)mac, sizeof(u8)*ETH_ALEN);
	mac_port_entry_t ** entry = &(mac_port_map.hash_table[hash_value]);
	if(!(*entry)) *entry = new_entry; // if the hash cell is empty
	else{
		while((*entry)->next) entry = &((*entry)->next); // find the tail of the hash cell
		(*entry)->next = new_entry; // add the entry to the hash cell
	}
	pthread_mutex_unlock(&mac_port_map.lock);
}

void dump_mac_port_table()
{
	mac_port_entry_t *entry = NULL;
	time_t now = time(NULL);

	fprintf(stdout, "dumping the mac_port table:\n");

	pthread_mutex_lock(&mac_port_map.lock);
	for (int i = 0; i < HASH_8BITS; i++) {
		entry = mac_port_map.hash_table[i];
		while (entry) {
			fprintf(stdout, ETHER_STRING " -> %s, %d\n", ETHER_FMT(entry->mac), \
					entry->iface->name, (int)(now - entry->visited));
			entry = entry->next;
		}
	}
	pthread_mutex_unlock(&mac_port_map.lock);
}

int sweep_aged_mac_port_entry()
{
	// TODO: implement the sweeping process here
	// fprintf(stdout, "TODO: implement the sweeping process here.\n");
	mac_port_entry_t *entry = NULL, *tmp = NULL;
	time_t now = time(NULL);
	// fprintf(stdout, "Sweeping aged mac port entry.\n");
	pthread_mutex_lock(&mac_port_map.lock);
	for (int i = 0; i < HASH_8BITS; i++) {
		entry = mac_port_map.hash_table[i];
		if(!entry) continue;
		tmp = entry->next;
		while(tmp){
			entry->next = tmp->next;
			if(((int)(now - tmp->visited)) > MAC_PORT_TIMEOUT){
				fprintf(stdout, ETHER_STRING " rm -> %s, %d\n", ETHER_FMT(tmp->mac), \
						tmp->iface->name, (int)(now - tmp->visited));				
				free(tmp);
			}
			tmp = entry->next;
		}
	}
	pthread_mutex_unlock(&mac_port_map.lock);
	return 0;
}

void * sweeping_mac_port_thread(void *nil)
{
	while (1) {
		sleep(1);
		int n = sweep_aged_mac_port_entry();

		if (n > 0)
			log(DEBUG, "%d aged entries in mac_port table are removed.\n", n);
	}

	return NULL;
}
