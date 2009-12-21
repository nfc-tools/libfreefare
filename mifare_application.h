#ifndef __MAD_DATA_H__
#define __MAD_DATA_H__

#include <mad.h>

MifareSectorNumber *mifare_application_alloc (Mad mad, MadAid aid, size_t size);
void	 mifare_application_free (Mad mad, MadAid aid);

MifareSectorNumber *mifare_application_find (Mad mad, MadAid aid);


#endif /* !__MAD_DATA_H__ */
