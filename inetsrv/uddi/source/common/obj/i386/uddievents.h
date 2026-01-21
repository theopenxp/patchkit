--------------------------------------------------------------------

 Event categories and message placeholders for UDDI.
 If you change this file, run buildeventdll.cmd to rebuild the dll.

--------------------------------------------------------------------

 Category Strings

//
//  Values are 32 bit values layed out as follows:
//
//   3 3 2 2 2 2 2 2 2 2 2 2 1 1 1 1 1 1 1 1 1 1
//   1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
//  +---+-+-+-----------------------+-------------------------------+
//  |Sev|C|R|     Facility          |               Code            |
//  +---+-+-+-----------------------+-------------------------------+
//
//  where
//
//      Sev - is the severity code
//
//          00 - Success
//          01 - Informational
//          10 - Warning
//          11 - Error
//
//      C - is the Customer code flag
//
//      R - is a reserved bit
//
//      Facility - is the facility code
//
//      Code - is the facility's status code
//
//
// Define the facility codes
//


//
// Define the severity codes
//


//
// MessageId: CATEGORY_NONE
//
// MessageText:
//
//  None
//
#define CATEGORY_NONE                    0x00000000L

//
// MessageId: CATEGORY_CONFIG
//
// MessageText:
//
//  Config
//
#define CATEGORY_CONFIG                  0x00000001L

//
// MessageId: CATEGORY_SOAP
//
// MessageText:
//
//  Soap
//
#define CATEGORY_SOAP                    0x00000002L

//
// MessageId: CATEGORY_DATA
//
// MessageText:
//
//  Data
//
#define CATEGORY_DATA                    0x00000003L

//
// MessageId: CATEGORY_AUTHORIZATION
//
// MessageText:
//
//  Authorization
//
#define CATEGORY_AUTHORIZATION           0x00000004L

//
// MessageId: CATEGORY_WEBSITE
//
// MessageText:
//
//  Website
//
#define CATEGORY_WEBSITE                 0x00000005L

//
// MessageId: CATEGORY_REPLICATION
//
// MessageText:
//
//  Replication
//
#define CATEGORY_REPLICATION             0x00000006L

------------------------------------------------
 Start of Event Messages

 There are approx 200 entries, number from 100 to 300


//
// MessageId: 0x00000064L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x00000065L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x00000066L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x00000067L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x00000068L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x00000069L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x0000006AL (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x0000006BL (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x0000006CL (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x0000006DL (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x0000006EL (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x0000006FL (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x00000070L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x00000071L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x00000072L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x00000073L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x00000074L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x00000075L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x00000076L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x00000077L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x00000078L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x00000079L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x0000007AL (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x0000007BL (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x0000007CL (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x0000007DL (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x0000007EL (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x0000007FL (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x00000080L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x00000081L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x00000082L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x00000083L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x00000084L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x00000085L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x00000086L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x00000087L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x00000088L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x00000089L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x0000008AL (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x0000008BL (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x0000008CL (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x0000008DL (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x0000008EL (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x0000008FL (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x00000090L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x00000091L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x00000092L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x00000093L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x00000094L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x00000095L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x00000096L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x00000097L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x00000098L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x00000099L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x0000009AL (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x0000009BL (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x0000009CL (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x0000009DL (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x0000009EL (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x0000009FL (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x000000A0L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x000000A1L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x000000A2L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x000000A3L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x000000A4L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x000000A5L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x000000A6L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x000000A7L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x000000A8L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x000000A9L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x000000AAL (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x000000ABL (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x000000ACL (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x000000ADL (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x000000AEL (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x000000AFL (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x000000B0L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x000000B1L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x000000B2L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x000000B3L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x000000B4L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x000000B5L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x000000B6L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x000000B7L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x000000B8L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x000000B9L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x000000BAL (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x000000BBL (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x000000BCL (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x000000BDL (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x000000BEL (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x000000BFL (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x000000C0L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x000000C1L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x000000C2L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x000000C3L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x000000C4L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x000000C5L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x000000C6L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x000000C7L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x000000C8L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x000000C9L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x000000CAL (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x000000CBL (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x000000CCL (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x000000CDL (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x000000CEL (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x000000CFL (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x000000D0L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x000000D1L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x000000D2L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x000000D3L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x000000D4L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x000000D5L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x000000D6L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x000000D7L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x000000D8L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x000000D9L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x000000DAL (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x000000DBL (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x000000DCL (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x000000DDL (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x000000DEL (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x000000DFL (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x000000E0L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x000000E1L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x000000E2L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x000000E3L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x000000E4L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x000000E5L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x000000E6L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x000000E7L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x000000E8L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x000000E9L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x000000EAL (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x000000EBL (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x000000ECL (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x000000EDL (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x000000EEL (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x000000EFL (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x000000F0L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x000000F1L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x000000F2L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x000000F3L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x000000F4L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x000000F5L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x000000F6L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x000000F7L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x000000F8L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x000000F9L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x000000FAL (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x000000FBL (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x000000FCL (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x000000FDL (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x000000FEL (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x000000FFL (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x00000100L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x00000101L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x00000102L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x00000103L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x00000104L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x00000105L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x00000106L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x00000107L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x00000108L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x00000109L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x0000010AL (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x0000010BL (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x0000010CL (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x0000010DL (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x0000010EL (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x0000010FL (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x00000110L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x00000111L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x00000112L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x00000113L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x00000114L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x00000115L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x00000116L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x00000117L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x00000118L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x00000119L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x0000011AL (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x0000011BL (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x0000011CL (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x0000011DL (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x0000011EL (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x0000011FL (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x00000120L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x00000121L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x00000122L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x00000123L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x00000124L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x00000125L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x00000126L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x00000127L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x00000128L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x00000129L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x0000012AL (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x0000012BL (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x0000012CL (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x0000012DL (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x0000012EL (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x0000012FL (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x00000130L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x00000131L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x00000132L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x00000133L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x00000134L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x00000135L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x00000136L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x00000137L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x00000138L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x00000139L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x0000013AL (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x0000013BL (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x0000013CL (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x0000013DL (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x0000013EL (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x0000013FL (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x00000140L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x00000141L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x00000142L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x00000143L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x00000144L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x00000145L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x00000146L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x00000147L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x00000148L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x00000149L (No symbolic name defined)
//
// MessageText:
//
//  %1
//


//
// MessageId: 0x0000014AL (No symbolic name defined)
//
// MessageText:
//
//  %1
//


