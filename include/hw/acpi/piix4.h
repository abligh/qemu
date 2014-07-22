#ifndef HW_ACPI_PIIX4_H
#define HW_ACPI_PIIX4_H

#include "qemu/typedefs.h"

Object *piix4_pm_find(void);
void piix4_pm_class_fix_compat(void);

#endif
