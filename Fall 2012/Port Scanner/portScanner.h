#define MAX_IP_ADDRESS_LENGTH 50

enum port_state {
	PORT_STATE_OPEN, PORT_STATE_CLOSED, PORT_STATE_FILTERED, PORT_STATE_UNFILTERED, PORT_STATE_OPEN_FILTERED, PORT_STATE_UNKNOWN
};

struct task_data {
	unsigned short  port;
	char            ip_address[MAX_IP_ADDRESS_LENGTH];
	int		protocol;
	enum port_state syn_state;
	enum port_state null_state;
	enum port_state fin_state;
	enum port_state xmax_state;
	enum port_state ack_state;
	enum port_state protocol_state;
};
