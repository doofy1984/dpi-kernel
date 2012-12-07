#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <getopt.h>
#include <iptables.h>

#include "ipt_NSC.h"

#define MAX_FN_LEN 256
#define PACKET_TO_CHECK_DEFAULT 10

static void
help(void)
{
    printf(
		"NSC v%s .\n"
	    "	--cfgfile <filepath>  : Specify the configuration file path.\n"
		"	--indev	<eth0,eth1...> : Specify the input device when do tuple-match.\n",
		NSC_VERSION);
}
static void
init(struct ipt_entry_target *t, unsigned int *nfcache)
{	
}

static struct option opts[] = {
	{ .name = "cfgfile",   .has_arg = 1, .flag = 0, .val = '1' },
	{ .name = "indev",     .has_arg = 1, .flag = 0, .val = '2' },
	{ .name = 0 }
};

static inline int
check_ucfg(const struct user_config *ucfg)
{
	return (ucfg->app_code > 0 && ucfg->priority > 0);
}

void
read_ucfg(const char *line, struct ipt_nsc_target_info *info)
{
	struct user_config ucfg;
	sscanf(line, "[%u,%u]", &ucfg.app_code, &ucfg.priority);
	if(!check_ucfg(&ucfg)) return;
	printf("user config: [app_code : %u ; priority : %u] \n", ucfg.app_code, ucfg.priority);
	/* assign if valid */
	info->cfg[info->cfg_count].app_code = ucfg.app_code;
	info->cfg[info->cfg_count].priority = ucfg.priority;
	info->cfg_count++;
}


static inline int
check_tuple(const struct match_tuple *tuple)
{
	/* tuple_mask [1,63] or (32768, 32832) */
	return ((tuple->proto == 6 || tuple->proto == 17) &&
		   ((tuple->tuple_mask > 0 && tuple->tuple_mask < 64) ||
		    (tuple->tuple_mask > 32768 && tuple->tuple_mask < 32832)));
}
/*
	uint8_t  proto;
	uint16_t tuple_mask;
	uint32_t src_ip;
	uint32_t dst_ip;
	uint16_t src_port;
	uint16_t dst_port;
	uint16_t plen_min;
	uint16_t plen_max;
	uint32_t app_code;
*/
/*
	sscanf :
	%u : 32 bit
	%hu : 16 bit
	%lu : 64 bit
	%hhu : 8 bit
	length modifier : hh , h , l , ll
*/
void
read_tuple(const char *line, struct ipt_nsc_target_info *info)
{
	struct match_tuple tuple;
	sscanf(line, "(%hhu,%hu,%u,%u,%hu,%hu,%hu,%hu,%u)",
		&tuple.proto,
		&tuple.tuple_mask,
		&tuple.src_ip,
		&tuple.dst_ip,
		&tuple.src_port,
		&tuple.dst_port,
		&tuple.plen_min,
		&tuple.plen_max,
		&tuple.app_code);

	if(!check_tuple(&tuple)) return;

	/* assign if valid */
	info->mtuples[info->mtuple_count].proto = tuple.proto;
	info->mtuples[info->mtuple_count].tuple_mask = tuple.tuple_mask;
	info->mtuples[info->mtuple_count].src_ip = tuple.src_ip;
	info->mtuples[info->mtuple_count].dst_ip = tuple.dst_ip;
	info->mtuples[info->mtuple_count].src_port = tuple.src_port;
	info->mtuples[info->mtuple_count].dst_port = tuple.dst_port;
	info->mtuples[info->mtuple_count].plen_max = tuple.plen_max;
	info->mtuples[info->mtuple_count].plen_min = tuple.plen_min;
	info->mtuples[info->mtuple_count].app_code = tuple.app_code;
	info->mtuple_count++;
	printf(".proto=%hhu.tuple_mask=%hu.src_ip=%u.dst_ip=%u.src_port=%hu.dst_port=%hu.plen_min=%hu.plen_max=%hu.app_code=%u\n",
		tuple.proto,
		tuple.tuple_mask,
		tuple.src_ip,
		tuple.dst_ip,
		tuple.src_port,
		tuple.dst_port,
		tuple.plen_min,
		tuple.plen_max,
		tuple.app_code);
}

/* read config file for ipt_NSC */
int
read_config(const char *filename, struct ipt_nsc_target_info *info)
{
	FILE *config_file;
	char *line = NULL;
	size_t len;

	info->pkt2check = PACKET_TO_CHECK_DEFAULT;
	info->indev_count = 0;
	/* if cfg_count == 0 , no protocol will be classified */
	info->cfg_count = 0;
	/* if mtuple_count == 0, no tuple-match will be done */
	info->mtuple_count = 0;
	int be_set = 0;

	config_file = fopen(filename, "r");
	/* BAD NEWS: Configuration file does not exist
	 * maybe missing... so we have to skip this
	 */
	if(!config_file) return 0;

	while(getline(&line, &len, config_file) != -1)
	{
		/* skip comments */
		if(line[0] == '#') continue;
		/* if windows format, make sure! */
		if(line[strlen(line) - 2] == '\r' && line[strlen(line) - 1] == '\n')
		{
			line[strlen(line) - 2] = '\0';
		}
		/* if there is a newline at end of line */
		if(line[strlen(line) - 1] == '\n')
			line[strlen(line) - 1] = '\0';
		if(be_set == 0)
		{
			if(strncmp(line, "pkt2check=", strlen("pkt2check=")) == 0)
			{
				info->pkt2check = atoi(&line[strlen("pkt2check=")]);
				printf("Hint: found pkt2check value %d. \n", info->pkt2check); 
				be_set = 1;
			}
			if(info->pkt2check > 1000 || info->pkt2check < 3)
			{
				printf("Warning: invalid pkt2check value %d, set to 10. \n", info->pkt2check); 
				info->pkt2check = 10;
			}
			continue;
		}
		if(line[0] == '[')
		{
			/* core dump if lack of this check */
			if (info->cfg_count >= CONFIG_MAX)
			{
				printf("Warning: exceed max config count, this line will be ignored.\n");
				continue;
			}
			read_ucfg(line, info);
			continue;
		}
		if(line[0] == '(')
		{
			if (info->mtuple_count >= MTUPLE_MAX)
			{
				printf("Warning: exceed max mtuple count, this line will be ignored.\n");
				continue;
			}
			read_tuple(line, info);
			continue;
		}
	}
	if(line) free(line);
	fclose(config_file);
	return 1;
}

#define LIBIPT_NSC_CONFIG	1
#define LIBIPT_NSC_INDEV	2

static int
parse(int c, char **argv, int invert, unsigned int *flags,
      const struct ipt_entry *entry,
      struct ipt_entry_target **target)
{
	struct ipt_nsc_target_info *info
		= (struct ipt_nsc_target_info *)(*target)->data;

	switch (c) {
		case '1':
			if ((*flags & LIBIPT_NSC_CONFIG) == LIBIPT_NSC_CONFIG)
				exit_error(PARAMETER_PROBLEM,
					"NSC: Can't specify --cfgfile twice\n");
			check_inverse(optarg, &invert, &optind, 0);
			//printf("optarg = #%s# ; argv[optind-1] = #%s#\n", optarg, argv[optind-1]);
			if (invert) exit_error(PARAMETER_PROBLEM, "NSC: invert [!] is not allowed.\n");
			if(strlen(argv[optind-1]) >= MAX_FN_LEN)
				exit_error(PARAMETER_PROBLEM,
					"NSC: Configuration file name too long.\n");
			if (!read_config(optarg, info))
				exit_error(PARAMETER_PROBLEM, "NSC: failed when load configuration file.\n");
			*flags += LIBIPT_NSC_CONFIG;
			break;
		case '2':
			if ((*flags & LIBIPT_NSC_INDEV) == LIBIPT_NSC_INDEV)
				exit_error(PARAMETER_PROBLEM,
					"NSC: Can't specify --indev twice.\n");
			check_inverse(optarg, &invert, &optind, 0);
			//printf("optarg = #%s# ; argv[optind-1] = #%s#\n", optarg, argv[optind-1]);
			if (invert) exit_error(PARAMETER_PROBLEM, "NSC: invert [!] is not allowed.\n");
			/* format : --indev eth1,eth2 */
			char *t = optarg;
			char *p = t;
			int indev_index = 0;
			int len = 0;
			while (1)
			{
				t++;
				len++;
				if (*t == ',')
				{
					strncpy(info->indev[indev_index], p, len);
					/* strncpy wont add \0 to a string */
					info->indev[indev_index][len] = '\0';
					printf("info->indev[%d]=#%s#\n", indev_index, info->indev[indev_index]);
					t++;
					p = t;
					len = 0;
					indev_index++;
					continue;
				}
				if (*t == '\0')
				{
					strncpy(info->indev[indev_index], p, len);
					info->indev[indev_index][len] = '\0';
					printf("info->indev[%d]=#%s#\n", indev_index, info->indev[indev_index]);
					break;
				}
			}
			info->indev_count = indev_index + 1;
			*flags += LIBIPT_NSC_INDEV;
			break;
		default:
			return 0;
	}
	return 1;
}

static void
final_check(unsigned int flags)
{
	if ((flags & LIBIPT_NSC_CONFIG) != LIBIPT_NSC_CONFIG || (flags & LIBIPT_NSC_INDEV) != LIBIPT_NSC_INDEV)
		exit_error(PARAMETER_PROBLEM, "NSC: lack of options.\n");
}

/* Prints out the matchinfo. */
static void print(const struct ipt_ip *ip,
      const struct ipt_entry_target *target,
      int numeric)
{
	struct ipt_nsc_target_info *info
		= (struct ipt_nsc_target_info *)target->data;
	//printf("NSC v%s ", NSC_VERSION);
	int idx;
	printf("Config_file: /usr/local/nswcf/param/ipt_nsc_cfg ");
	printf("Input_device: ");
	for (idx = 0; idx < info->indev_count -	1; idx++)
		printf("%s,", info->indev[idx]);
	printf("%s ",info->indev[info->indev_count - 1]);
}

/* Saves the union ipt_targinfo in parsable form to stdout. */
static void save(const struct ipt_ip *ip,
		 const struct ipt_entry_target *target)
{
	struct ipt_nsc_target_info *info
		= (struct ipt_nsc_target_info *)target->data;
	int idx;
	printf("--cfgfile /usr/local/nswcf/param/ipt_nsc_cfg ");
	printf("--indev ");
	for (idx = 0; idx < info->indev_count -	1; idx++)
		printf("%s,", info->indev[idx]);
	printf("%s ",info->indev[info->indev_count - 1]);
}

static 
struct iptables_target nsc= 
{ 
	.next           = NULL,
	.name           = "NSC",
	.version        = IPTABLES_VERSION,
    .size           = IPT_ALIGN(sizeof(struct ipt_nsc_target_info)),
    .userspacesize  = IPT_ALIGN(sizeof(struct ipt_nsc_target_info)),
	.init			= &init,
    .help           = &help,
    .parse          = &parse,
    .final_check    = &final_check,
    .print          = &print,
    .save           = &save,
    .extra_opts     = opts
};
					    


void _init(void)
{
    register_target(&nsc);
}
